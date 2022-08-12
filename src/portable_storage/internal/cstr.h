#pragma once

#define TO_CSTR(p) reinterpret_cast<const char*>(p)
#define SPAN_TO_CSTR(span) reinterpret_cast<const char*>(span.begin())
