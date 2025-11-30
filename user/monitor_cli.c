#include <windows.h>
#include <stdio.h>

#include "monitor_client.h"

static void PrintLastError(const char* where, DWORD err)
{
    fprintf(stderr, "%s failed: %lu\n", where, (unsigned long)err);
}

int main(void)
{
    HANDLE hMon = NULL;
    DWORD err = MonOpen(&hMon);
    if (err != ERROR_SUCCESS) {
        PrintLastError("MonOpen", err);
        return 1;
    }

    ULONG version = 0;
    err = MonGetVersion(hMon, &version);
    if (err == ERROR_SUCCESS) {
        printf("Driver version: 0x%08lX\n", (unsigned long)version);
    }

    MONITOR_SETTINGS settings;
    ZeroMemory(&settings, sizeof(settings));
    settings.Size = sizeof(settings);
    settings.EnableMonitoring = 1;
    settings.EnableTelemetry = 1;
    settings.EnableEncryption = 0;
    settings.RateLimitPerSec = 0; /* use default */

    err = MonEnable(hMon, &settings);
    if (err != ERROR_SUCCESS) {
        PrintLastError("MonEnable", err);
        MonClose(hMon);
        return 1;
    }

    err = MonScanNow(hMon);
    if (err != ERROR_SUCCESS) {
        PrintLastError("MonScanNow", err);
    }

    EVENT_BLOB buf;
    ULONG bytes = 0;
    err = MonFetchEvent(hMon, &buf, sizeof(buf), &bytes);
    if (err == ERROR_SUCCESS) {
        printf("Fetched event: type=%u size=%lu\n", buf.Type, (unsigned long)bytes);
    } else {
        printf("MonFetchEvent returned %lu (this may be normal if no events).\n", (unsigned long)err);
    }

    MONITOR_STATS stats;
    err = MonGetStats(hMon, &stats);
    if (err == ERROR_SUCCESS) {
        printf("Stats: TotalAllocations=%llu IopMcDetections=%llu CrossVmDetections=%llu PolicyViolations=%llu DroppedEvents=%llu\n",
            (unsigned long long)stats.TotalAllocations,
            (unsigned long long)stats.IopMcDetections,
            (unsigned long long)stats.CrossVmDetections,
            (unsigned long long)stats.PolicyViolations,
            (unsigned long long)stats.DroppedEvents);
    } else {
        PrintLastError("MonGetStats", err);
    }

    MonDisable(hMon);
    MonClose(hMon);
    return 0;
}
