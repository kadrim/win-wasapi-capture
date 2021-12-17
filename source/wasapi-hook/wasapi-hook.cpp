#include <string>
#include <windows.h>
#include <inttypes.h>
#include <audioclient.h>
#include <mmdeviceapi.h>
#include <util/threading.h>
#include "funchook.h"
#include "../wasapi-hook-info.h"

HMODULE this_module;

typedef HRESULT (STDMETHODCALLTYPE *release_buffer_t)(
	IAudioRenderClient*, UINT32, DWORD);
typedef HRESULT (STDMETHODCALLTYPE *get_buffer_t)(
	IAudioRenderClient*, UINT32, BYTE**);

static struct func_hook release_buffer;
static struct func_hook get_buffer;
void *release_buffer_addr;
void *get_buffer_addr;
HANDLE pipe;
HANDLE shmem;
shmem_data* shared_data;
bool terminating = false;

HANDLE event_capture_start;
HANDLE event_capture_stop;
HANDLE event_capture_restart;
HANDLE event_ready;
HANDLE event_exit;
HANDLE event_packet_sent;
HANDLE event_keepalive;

CRITICAL_SECTION cs_release_buffer;
CRITICAL_SECTION cs_get_buffer;

size_t format_ptr_offset = 0;
uint8_t *acquired_render_buffer = nullptr;
DWORD32 acquired_frames = 0;

static inline uint64_t get_clockfreq()
{
	static bool have_clockfreq = false;
	static LARGE_INTEGER clock_freq;

	if (!have_clockfreq) {
		QueryPerformanceFrequency(&clock_freq);
		have_clockfreq = true;
	}

	return clock_freq.QuadPart;
}

static inline uint64_t os_gettime_ns()
{
	LARGE_INTEGER current_time = { 0 };
	double time_val;

	QueryPerformanceCounter(&current_time);
	time_val = (double)current_time.QuadPart;
	time_val *= 1000000000.0;
	time_val /= (double)get_clockfreq();

	return (uint64_t)time_val;
}

static HRESULT STDMETHODCALLTYPE hook_get_buffer(IAudioRenderClient *client,
						     UINT32 NumFramesRequested,
						     BYTE **ppData)
{
	EnterCriticalSection(&cs_get_buffer);

	HRESULT hr;

	// Call original
	unhook(&get_buffer);
	get_buffer_t call = (get_buffer_t)get_buffer.call_addr;
	hr = call(client, NumFramesRequested, ppData);
	rehook(&get_buffer);

	acquired_render_buffer = (hr == S_OK) ? *ppData : nullptr;
	acquired_frames = NumFramesRequested;

	LeaveCriticalSection(&cs_get_buffer);

	return hr;
}

static HRESULT STDMETHODCALLTYPE hook_release_buffer(
	IAudioRenderClient *client, UINT32 frames_written, DWORD flags)
{
	EnterCriticalSection(&cs_release_buffer);

	HRESULT hr;
	WAVEFORMATEX *wfex = nullptr;

	// get timestamp
	static bool have_clockfreq = false;
	static LARGE_INTEGER clock_freq;
	double time_val;

	LARGE_INTEGER current_time = { 0 };
	if (!have_clockfreq) {
		QueryPerformanceFrequency(&clock_freq);
		have_clockfreq = true;
	}

	QueryPerformanceCounter(&current_time);
	time_val = (double)current_time.QuadPart;
	time_val *= 1000000000.0;
	time_val /= (double)clock_freq.QuadPart;

	if (acquired_render_buffer) {
		if (!format_ptr_offset) {
			for (size_t i = 0; i < 0x1000; ++i) {
				try {
					if (*(uint8_t **)(((uint8_t *)client) +
							  i) ==
					    acquired_render_buffer) {
						format_ptr_offset =
							i - sizeof(void *) * 2;
						break;
					}
				} catch (...) {
				}
			}
		}

		if (format_ptr_offset)
			wfex = *(WAVEFORMATEX **)(((uint8_t *)client) +
						  format_ptr_offset);
	}

	if (wfex && frames_written > 0 && frames_written == acquired_frames) {
		WAVEFORMATEXTENSIBLE *wfext = (WAVEFORMATEXTENSIBLE *)wfex;
		size_t data_length = frames_written * wfex->nChannels *
				     wfex->wBitsPerSample / 8;

		// Write packet
		audio_packet_header packet_header;
		packet_header.magic = AUDIO_PACKET_MAGIC;
		packet_header.frames = frames_written;
		packet_header.data_length = (uint32_t)data_length;
		packet_header.timestamp = (uint64_t)time_val;
		packet_header.silent = (flags & AUDCLNT_BUFFERFLAGS_SILENT) !=
				       0;
		memcpy(&packet_header.wfext, wfext,
		       sizeof(WAVEFORMATEXTENSIBLE));

		if (pipe != INVALID_HANDLE_VALUE) {
			DWORD written = 0;
			WriteFile(pipe, &packet_header, sizeof(packet_header),
				  &written, nullptr);
			WriteFile(pipe, acquired_render_buffer,
				  (DWORD)data_length, &written, nullptr);

			os_atomic_inc_long(&shared_data->packets);
			SetEvent(event_packet_sent);
		}
	}

	// Call original
	unhook(&release_buffer);
	release_buffer_t call = (release_buffer_t)release_buffer.call_addr;
	hr = call(client, frames_written, flags);
	rehook(&release_buffer);

	acquired_render_buffer = nullptr;
	acquired_frames = 0;

	LeaveCriticalSection(&cs_release_buffer);

	return hr;
}

bool get_wasapi_offsets()
{
	HRESULT             hr;
	HMODULE             module;
	IMMDeviceEnumerator *enumerator;
	IMMDevice           *device;
	IAudioClient        *audio_client;
	WAVEFORMATEX        *wfex;
	REFERENCE_TIME      default_period;
	REFERENCE_TIME      minimum_period;
	IAudioRenderClient  *render_client;

	module = LoadLibrary(TEXT("AudioSes.dll"));
	if (module == NULL)
	{
		return false;
	}

	hr = CoCreateInstance(
		__uuidof(MMDeviceEnumerator),
		NULL,
		CLSCTX_ALL,
		__uuidof(IMMDeviceEnumerator),
		(void**)&enumerator);
	if (FAILED(hr)) {
		return false;
	}

	hr = enumerator->GetDefaultAudioEndpoint(eRender, eConsole, &device);
	enumerator->Release();
	if (FAILED(hr)) {
		return false;
	}

	hr = device->Activate(__uuidof(IAudioClient),
			CLSCTX_ALL, NULL, (void**)&audio_client);
	if (FAILED(hr)) {
		device->Release();
		return false;
	}

	hr = audio_client->GetDevicePeriod(&default_period, &minimum_period);
	if (FAILED(hr)) {
		audio_client->Release();
		device->Release();
		return false;
	}

	hr = audio_client->GetMixFormat(&wfex);
	if (FAILED(hr)) {
		audio_client->Release();
		device->Release();
		return false;
	}

	hr = audio_client->Initialize(
		AUDCLNT_SHAREMODE_SHARED,
		AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
		minimum_period,
		minimum_period,
		wfex,
		NULL);
	if (FAILED(hr)) {
		audio_client->Release();
		device->Release();
		return false;
	}

	hr = audio_client->GetService(__uuidof(IAudioRenderClient),
				(void**)&render_client);
	if (FAILED(hr)) {
		audio_client->Release();
		device->Release();
		return false;
	}

	release_buffer_addr = (void *)((*(uintptr_t **)render_client)[4]);
	get_buffer_addr = (void *)((*(uintptr_t **)render_client)[3]);

	render_client->Release();
	audio_client->Release();
	device->Release();

	return true;
}

void init_hook()
{
	hook_init(&release_buffer,
		release_buffer_addr,
		hook_release_buffer,
		"IAudioRenderClient::ReleaseBuffer");
	rehook(&release_buffer);
	hook_init(&get_buffer, get_buffer_addr, hook_get_buffer,
		  "IAudioRenderClient::GetBuffer");
	rehook(&get_buffer);
}

void init_pipe()
{
	std::string pipe_name("\\\\.\\pipe\\" STREAM_PIPE_NAME);
	pipe_name += std::to_string(GetCurrentProcessId());

	pipe = CreateFileA(pipe_name.c_str(), GENERIC_WRITE,
		0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

void free_pipe()
{
	CloseHandle(pipe);
}

void init_shared_memory()
{
	std::string shared_memory_name(SHMEM_NAME);
	shared_memory_name += std::to_string(GetCurrentProcessId());

	shmem = CreateFileMappingA(
		INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(shmem_data),
		shared_memory_name.c_str());
	shared_data = (shmem_data*)MapViewOfFile(
		shmem, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(shmem_data));
	memset(shared_data, 0, sizeof(shmem_data));
}

void free_shared_memory()
{
	UnmapViewOfFile(shared_data);
	CloseHandle(shmem);
}

void init_events()
{
#define CREATE_EVENT(name) CreateEventA( \
		nullptr, FALSE, FALSE, \
		(std::string(name) + std::to_string(GetCurrentProcessId())).c_str());

	event_capture_start   = CREATE_EVENT(EVENT_CAPTURE_START);
	event_capture_stop    = CREATE_EVENT(EVENT_CAPTURE_STOP);
	event_capture_restart = CREATE_EVENT(EVENT_CAPTURE_RESTART);
	event_ready           = CREATE_EVENT(EVENT_READY);
	event_exit            = CREATE_EVENT(EVENT_EXIT);
	event_packet_sent     = CREATE_EVENT(EVENT_PACKET_SENT);
	event_keepalive       = CREATE_EVENT(EVENT_KEEPALIVE);

#undef CREATE_EVENT
}

void free_events()
{
	CloseHandle(event_capture_start);
	CloseHandle(event_capture_stop);
	CloseHandle(event_capture_restart);
	CloseHandle(event_ready);
	CloseHandle(event_exit);
	CloseHandle(event_packet_sent);
	CloseHandle(event_keepalive);
}

void terminator_proc()
{
	while (!terminating) {
		ResetEvent(event_keepalive);
		DWORD result = WaitForSingleObject(event_keepalive, KEEPALIVE_TIMEOUT);
		if (result == WAIT_OBJECT_0) {
			// Check for exit signal
			result = WaitForSingleObject(event_exit, 0);
			if (result == WAIT_OBJECT_0) {
				terminating = true; // exit requested!
			}
			continue;
		} else {
			terminating = true; // timed-out
		}
	}

	EnterCriticalSection(&cs_release_buffer);
	unhook(&release_buffer);
	LeaveCriticalSection(&cs_release_buffer);

	EnterCriticalSection(&cs_get_buffer);
	unhook(&get_buffer);
	LeaveCriticalSection(&cs_get_buffer);

	Sleep(100); // make sure hook_release_buffer is complete

	free_events();
	free_pipe();
	free_shared_memory();

	FreeLibraryAndExitThread(this_module, 0);
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason_for_call, LPVOID reserved)
{
	static HANDLE terminator_thread;

	if (reason_for_call == DLL_PROCESS_ATTACH) {
		this_module = module;

		CoInitialize(NULL);
		get_wasapi_offsets();
		CoUninitialize();

		InitializeCriticalSection(&cs_get_buffer);
		InitializeCriticalSection(&cs_release_buffer);

		init_shared_memory();
		init_pipe();
		init_events();
		init_hook();

		terminator_thread = CreateThread(nullptr, 0,
			(LPTHREAD_START_ROUTINE)&terminator_proc,
			nullptr, 0, nullptr);

		SetEvent(event_ready);
	}

	return TRUE;
}
