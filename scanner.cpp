#include <windows.h>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <algorithm>

#ifdef _WIN32
    #define EXPORT extern "C" __declspec(dllexport)
#else
    #define EXPORT extern "C"
#endif

enum ScanType {
    SCAN_EXACT = 0,
    SCAN_RANGE = 1,
    SCAN_INCREASED = 2,
    SCAN_DECREASED = 3,
    SCAN_CHANGED = 4,
    SCAN_UNCHANGED = 5,
    SCAN_CHANGED_BY = 6
};

enum ValueType {
    TYPE_FLOAT32 = 0,
    TYPE_FLOAT64 = 1,
    TYPE_INT8 = 2,
    TYPE_UINT8 = 3,
    TYPE_INT16 = 4,
    TYPE_UINT16 = 5,
    TYPE_INT32 = 6,
    TYPE_UINT32 = 7,
    TYPE_INT64 = 8,
    TYPE_UINT64 = 9
};

struct ScanResult {
    uintptr_t address;
    double value;
};

template<typename T>
inline bool passes_filter_typed(T current, T previous, int scan_type, 
                               double value1, double value2, double tolerance) {
    switch (scan_type) {
        case SCAN_EXACT:
            if constexpr (std::is_floating_point<T>::value) {
                return std::abs((double)current - value1) <= tolerance;
            } else {
                return std::abs((double)current - value1) <= tolerance;
            }
        
        case SCAN_RANGE:
            return ((double)current >= value1) && ((double)current <= value2);
        
        case SCAN_INCREASED:
            return current > previous;
        
        case SCAN_DECREASED:
            return current < previous;
        
        case SCAN_CHANGED:
            if constexpr (std::is_floating_point<T>::value) {
                return std::abs((double)current - (double)previous) > tolerance;
            } else {
                return current != previous;
            }
        
        case SCAN_UNCHANGED:
            if constexpr (std::is_floating_point<T>::value) {
                return std::abs((double)current - (double)previous) <= tolerance;
            } else {
                return current == previous;
            }
        
        case SCAN_CHANGED_BY:
            {
                double delta = std::abs((double)current - (double)previous);
                return std::abs(delta - value2) <= tolerance;
            }
    }
    return false;
}

template<typename T>
int scan_buffer_typed(const unsigned char* buffer, size_t buffer_size, 
                      uintptr_t base_addr, int step,
                      int scan_type, double value1, double value2, double tolerance,
                      ScanResult* results, int max_results,
                      bool check_float_validity) {
    int found = 0;
    size_t size = sizeof(T);
    
    for (size_t i = 0; i + size <= buffer_size && found < max_results; i += step) {
        T val;
        memcpy(&val, buffer + i, size);
        
        // Skip invalid floats
        if (check_float_validity) {
            if constexpr (std::is_floating_point<T>::value) {
                if (std::isnan(val) || std::isinf(val)) {
                    continue;
                }
            }
        }
        
        // For first scan (no previous value), previous is meaningless
        bool match = false;
        if (scan_type == SCAN_EXACT || scan_type == SCAN_RANGE) {
            match = passes_filter_typed<T>(val, T(0), scan_type, value1, value2, tolerance);
        }
        
        if (match) {
            results[found].address = base_addr + i;
            results[found].value = (double)val;
            found++;
        }
    }
    
    return found;
}

EXPORT int scan_buffer_first_scan(
    const unsigned char* buffer,
    size_t buffer_size,
    uintptr_t base_addr,
    int value_type,
    int unaligned,
    int scan_type,
    double value1,
    double value2,
    double tolerance,
    ScanResult* results,
    int max_results
) {
    if (!buffer || !results || max_results <= 0) {
        return 0;
    }
    
    int step = 1;
    bool check_floats = true;
    
    switch (value_type) {
        case TYPE_FLOAT32:
            step = unaligned ? 1 : 4;
            return scan_buffer_typed<float>(buffer, buffer_size, base_addr, step,
                                           scan_type, value1, value2, tolerance,
                                           results, max_results, check_floats);
        
        case TYPE_FLOAT64:
            step = unaligned ? 1 : 8;
            return scan_buffer_typed<double>(buffer, buffer_size, base_addr, step,
                                            scan_type, value1, value2, tolerance,
                                            results, max_results, check_floats);
        
        case TYPE_INT8:
            step = unaligned ? 1 : 1;
            return scan_buffer_typed<int8_t>(buffer, buffer_size, base_addr, step,
                                            scan_type, value1, value2, tolerance,
                                            results, max_results, false);
        
        case TYPE_UINT8:
            step = unaligned ? 1 : 1;
            return scan_buffer_typed<uint8_t>(buffer, buffer_size, base_addr, step,
                                             scan_type, value1, value2, tolerance,
                                             results, max_results, false);
        
        case TYPE_INT16:
            step = unaligned ? 1 : 2;
            return scan_buffer_typed<int16_t>(buffer, buffer_size, base_addr, step,
                                             scan_type, value1, value2, tolerance,
                                             results, max_results, false);
        
        case TYPE_UINT16:
            step = unaligned ? 1 : 2;
            return scan_buffer_typed<uint16_t>(buffer, buffer_size, base_addr, step,
                                              scan_type, value1, value2, tolerance,
                                              results, max_results, false);
        
        case TYPE_INT32:
            step = unaligned ? 1 : 4;
            return scan_buffer_typed<int32_t>(buffer, buffer_size, base_addr, step,
                                             scan_type, value1, value2, tolerance,
                                             results, max_results, false);
        
        case TYPE_UINT32:
            step = unaligned ? 1 : 4;
            return scan_buffer_typed<uint32_t>(buffer, buffer_size, base_addr, step,
                                              scan_type, value1, value2, tolerance,
                                              results, max_results, false);
        
        case TYPE_INT64:
            step = unaligned ? 1 : 8;
            return scan_buffer_typed<int64_t>(buffer, buffer_size, base_addr, step,
                                             scan_type, value1, value2, tolerance,
                                             results, max_results, false);
        
        case TYPE_UINT64:
            step = unaligned ? 1 : 8;
            return scan_buffer_typed<uint64_t>(buffer, buffer_size, base_addr, step,
                                              scan_type, value1, value2, tolerance,
                                              results, max_results, false);
    }
    
    return 0;
}

template<typename T>
int rescan_addresses_typed(
    HANDLE process_handle,
    const uintptr_t* addresses,
    const double* previous_values,
    int num_addresses,
    int scan_type,
    double value1,
    double value2,
    double tolerance,
    ScanResult* results,
    int max_results
) {
    int found = 0;
    SIZE_T bytes_read;
    
    for (int i = 0; i < num_addresses && found < max_results; i++) {
        T current_val;
        
        if (ReadProcessMemory(process_handle, (LPCVOID)addresses[i], 
                             &current_val, sizeof(T), &bytes_read) &&
            bytes_read == sizeof(T)) {
            
            // Skip invalid floats
            if constexpr (std::is_floating_point<T>::value) {
                if (std::isnan(current_val) || std::isinf(current_val)) {
                    continue;
                }
            }
            
            T prev_val = (T)previous_values[i];
            
            if (passes_filter_typed<T>(current_val, prev_val, scan_type, 
                                      value1, value2, tolerance)) {
                results[found].address = addresses[i];
                results[found].value = (double)current_val;
                found++;
            }
        }
    }
    
    return found;
}

EXPORT int scan_buffer_next_scan(
    HANDLE process_handle,
    const uintptr_t* addresses,
    const double* previous_values,
    int num_addresses,
    int value_type,
    int scan_type,
    double value1,
    double value2,
    double tolerance,
    ScanResult* results,
    int max_results
) {
    if (!addresses || !previous_values || !results || max_results <= 0) {
        return 0;
    }
    
    switch (value_type) {
        case TYPE_FLOAT32:
            return rescan_addresses_typed<float>(process_handle, addresses, previous_values,
                                                num_addresses, scan_type, value1, value2,
                                                tolerance, results, max_results);
        
        case TYPE_FLOAT64:
            return rescan_addresses_typed<double>(process_handle, addresses, previous_values,
                                                 num_addresses, scan_type, value1, value2,
                                                 tolerance, results, max_results);
        
        case TYPE_INT8:
            return rescan_addresses_typed<int8_t>(process_handle, addresses, previous_values,
                                                 num_addresses, scan_type, value1, value2,
                                                 tolerance, results, max_results);
        
        case TYPE_UINT8:
            return rescan_addresses_typed<uint8_t>(process_handle, addresses, previous_values,
                                                  num_addresses, scan_type, value1, value2,
                                                  tolerance, results, max_results);
        
        case TYPE_INT16:
            return rescan_addresses_typed<int16_t>(process_handle, addresses, previous_values,
                                                  num_addresses, scan_type, value1, value2,
                                                  tolerance, results, max_results);
        
        case TYPE_UINT16:
            return rescan_addresses_typed<uint16_t>(process_handle, addresses, previous_values,
                                                   num_addresses, scan_type, value1, value2,
                                                   tolerance, results, max_results);
        
        case TYPE_INT32:
            return rescan_addresses_typed<int32_t>(process_handle, addresses, previous_values,
                                                  num_addresses, scan_type, value1, value2,
                                                  tolerance, results, max_results);
        
        case TYPE_UINT32:
            return rescan_addresses_typed<uint32_t>(process_handle, addresses, previous_values,
                                                   num_addresses, scan_type, value1, value2,
                                                   tolerance, results, max_results);
        
        case TYPE_INT64:
            return rescan_addresses_typed<int64_t>(process_handle, addresses, previous_values,
                                                  num_addresses, scan_type, value1, value2,
                                                  tolerance, results, max_results);
        
        case TYPE_UINT64:
            return rescan_addresses_typed<uint64_t>(process_handle, addresses, previous_values,
                                                   num_addresses, scan_type, value1, value2,
                                                   tolerance, results, max_results);
    }
    
    return 0;
}
