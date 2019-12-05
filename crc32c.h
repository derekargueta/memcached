#pragma once

typedef uint32_t (*crc_func)(uint32_t crc, const void *buf, size_t len);
crc_func crc32c;

void crc32c_init();
