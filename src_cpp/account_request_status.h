#pragma once
#include <cstdint>

// Results disappear in one step two seconds after the last request finishes.
// A new revision restarts the timer even when the result text is unchanged.
struct AccountRequestStatusTimer {
    uint64_t revision = 0;
    double deadline = 0;

    bool expired(bool working, uint64_t current_revision, bool has_result, double now) {
        if (revision != current_revision) {
            revision = current_revision;
            deadline = 0;
        }
        if (working || !has_result) { deadline = 0; return false; }
        if (!deadline) deadline = now + 2.0;
        return now >= deadline;
    }
};
