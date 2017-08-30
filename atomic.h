#pragma once

#include "base.h"

#define atomic_inc(ptr) __sync_fetch_and_add(ptr, 1)
#define atomic_dec(ptr) __sync_fetch_and_sub(ptr, 1)
#define atomic_read(ptr) __sync_fetch_and_add(ptr, 0)
#define atomic_cmpxchg(ptr, old_val, new_val) __sync_val_compare_and_swap(ptr, old_val, new_val)