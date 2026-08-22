#pragma once

// Keep this wrapper deliberately small. bindgen follows the Dokany headers and
// emits only the allowlisted public API selected by the generator.
#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#include "../src/dokany/dokan/dokan.h"
#include "../src/dokany/dokan/dokanc.h"
#include "../src/dokany/dokan/fileinfo.h"
