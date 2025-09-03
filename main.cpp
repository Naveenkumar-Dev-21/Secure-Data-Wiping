#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <devguid.h>
#include <ntddstor.h>
#pragma comment(lib, "setupapi.lib")
#else
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <scsi/sg.h>
#include <scsi/scsi.h>
#endif
#endif

// Function declarations
void analyze_usb_device_details(const char* device);
void analyze_mobile_device_type(const char* usb_device_path);
void list_all_usb_devices(void);

void check_hpa_dco_linux(const char* device) {
    char device_path[256];
    snprintf(device_path, sizeof(device_path), "/dev/%s", device);
    
    printf("=== HPA/DCO Analysis ===\n");
    
    int fd = open(device_path, O_RDONLY);
    if (fd < 0) {
        printf("Cannot open %s for HPA/DCO analysis (try running as root)\n", device_path);
        return;
    }
    
    // Check if it's NVMe device
    if (strncmp(device, "nvme", 4) == 0) {
        printf("NVMe Device Detected - Checking security features...\n");
        
        unsigned long long size;
        if (ioctl(fd, BLKGETSIZE64, &size) == 0) {
            printf("Device Size: %llu bytes (%.2f GB)\n", 
                   size, size / (1024.0 * 1024.0 * 1024.0));
        }
        
        // Check NVMe namespace information
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "nvme list | grep %s", device_path);
        FILE *nvme_output = popen(cmd, "r");
        if (nvme_output) {
            char line[512];
            if (fgets(line, sizeof(line), nvme_output)) {
                printf("NVMe Info: %s", line);
            }
            pclose(nvme_output);
        }
        
        // Check for NVMe security features
        snprintf(cmd, sizeof(cmd), "nvme id-ctrl %s 2>/dev/null | grep -E 'ses|cfs|Format NVM|Crypto Erase'", device_path);
        nvme_output = popen(cmd, "r");
        if (nvme_output) {
            char line[256];
            int found_security = 0;
            printf("NVMe Security Features:\n");
            while (fgets(line, sizeof(line), nvme_output)) {
                printf("  %s", line);
                found_security = 1;
            }
            if (!found_security) {
                printf("  Standard NVMe security features available\n");
            }
            pclose(nvme_output);
        }
        
        printf("HPA/DCO Status: Not applicable for NVMe devices\n");
        printf("Note: NVMe uses different security mechanisms than ATA devices\n");
        
    } else {
        // Check if it's an ATA device
        struct hd_driveid drive_id;
        if (ioctl(fd, HDIO_GET_IDENTITY, &drive_id) == 0) {
            printf("ATA Device Detected - Checking for HPA/DCO...\n");
            
            // Get accessible capacity
            unsigned long long accessible_max = 0;
            unsigned long long kernel_size = 0;
            if (ioctl(fd, BLKGETSIZE64, &kernel_size) == 0) {
                accessible_max = kernel_size / 512; // Convert bytes to sectors
                printf("Accessible Capacity: %llu sectors (%.2f GB)\n", 
                       accessible_max, (accessible_max * 512.0) / (1024.0 * 1024.0 * 1024.0));
            }
            
            // Check for HPA (Host Protected Area)
            printf("HPA Status: ");
            if (drive_id.command_set_2 & 0x0400) { // HPA feature set supported
                printf("HPA Feature Supported\n");
                
                // Try using hdparm to get more detailed info
                char cmd[512];
                snprintf(cmd, sizeof(cmd), "hdparm -N %s 2>/dev/null", device_path);
                FILE *hdparm_output = popen(cmd, "r");
                if (hdparm_output) {
                    char line[256];
                    printf("HPA Information:\n");
                    while (fgets(line, sizeof(line), hdparm_output)) {
                        if (strstr(line, "max sectors") || strstr(line, "HPA") || 
                            strstr(line, "sectors") || strstr(line, "enabled")) {
                            printf("  %s", line);
                        }
                    }
                    pclose(hdparm_output);
                } else {
                    printf("  Unable to get detailed HPA info (hdparm not available)\n");
                }
            } else {
                printf("HPA Feature Not Supported\n");
            }
            
            // Check for DCO (Device Configuration Overlay)
            printf("DCO Status: ");
            if (drive_id.command_set_2 & 0x0800) { // DCO feature set supported
                printf("DCO Feature Supported\n");
                printf("  ⚠️  Warning: DCO may hide device capacity and features\n");
                
                // Try to get DCO information
                char dco_cmd[512];
                snprintf(dco_cmd, sizeof(dco_cmd), "hdparm --dco-identify %s 2>/dev/null", device_path);
                FILE *dco_output = popen(dco_cmd, "r");
                if (dco_output) {
                    char line[256];
                    printf("DCO Information:\n");
                    while (fgets(line, sizeof(line), dco_output)) {
                        if (strstr(line, "Real max sectors") || strstr(line, "DCO")) {
                            printf("  %s", line);
                        }
                    }
                    pclose(dco_output);
                }
            } else {
                printf("DCO Feature Not Supported\n");
            }
            
            // Additional security features
            printf("\n=== ATA Security Features ===\n");
            
            // Security feature set
            if (drive_id.command_set_1 & 0x0002) {
                printf("Security Feature Set: ✓ Supported\n");
                
                // Get detailed security status
                char sec_cmd[512];
                snprintf(sec_cmd, sizeof(sec_cmd), "hdparm -I %s 2>/dev/null | grep -A5 -B5 -i security", device_path);
                FILE *sec_output = popen(sec_cmd, "r");
                if (sec_output) {
                    char line[256];
                    while (fgets(line, sizeof(line), sec_output)) {
                        if (strstr(line, "Security") || strstr(line, "enabled") || 
                            strstr(line, "locked") || strstr(line, "erase")) {
                            printf("  %s", line);
                        }
                    }
                    pclose(sec_output);
                }
            } else {
                printf("Security Feature Set: ✗ Not Supported\n");
            }
            
            // Sanitize feature set (ACS-2)
            if (drive_id.command_set_2 & 0x1000) {
                printf("Sanitize Feature: ✓ Supported\n");
            } else {
                printf("Sanitize Feature: ✗ Not Supported\n");
            }
            
        } else {
            printf("Not an ATA device or unable to get ATA identity\n");
            
            // For non-ATA devices, try alternative methods
            printf("Attempting alternative capacity detection...\n");
            
            unsigned long long size;
            if (ioctl(fd, BLKGETSIZE64, &size) == 0) {
                printf("Device Size: %llu bytes (%.2f GB)\n", 
                       size, size / (1024.0 * 1024.0 * 1024.0));
            }
            
            // Check if it's a SCSI device
            char scsi_path[256];
            snprintf(scsi_path, sizeof(scsi_path), "/sys/block/%s/device/type", device);
            FILE *type_file = fopen(scsi_path, "r");
            if (type_file) {
                int device_type;
                if (fscanf(type_file, "%d", &device_type) == 1) {
                    printf("SCSI Device Type: %d ", device_type);
                    switch (device_type) {
                        case 0: printf("(Direct Access - Disk)\n"); break;
                        case 5: printf("(CD-ROM)\n"); break;
                        case 7: printf("(Optical Memory)\n"); break;
                        default: printf("(Other)\n"); break;
                    }
                }
                fclose(type_file);
            }
            
            printf("HPA/DCO Status: Not applicable for this device type\n");
        }
    }
    
    close(fd);
}

void check_smart_info_linux(const char* device) {
    printf("\n=== SMART Status ===\n");
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "smartctl -H /dev/%s 2>/dev/null", device);
    
    FILE *smart_output = popen(cmd, "r");
    if (smart_output) {
        char line[256];
        int found_info = 0;
        while (fgets(line, sizeof(line), smart_output)) {
            if (strstr(line, "SMART overall-health") || 
                strstr(line, "SMART Health Status") ||
                strstr(line, "PASSED") || 
                strstr(line, "FAILED")) {
                printf("%s", line);
                found_info = 1;
            }
        }
        pclose(smart_output);
        
        if (!found_info) {
            printf("SMART information not available (smartctl not installed or device doesn't support SMART)\n");
        }
    } else {
        printf("Cannot check SMART status (smartctl not available)\n");
    }
}

void analyze_usb_device_details(const char* device) {
    printf("\n=== USB Device Analysis ===\n");
    
    // Get USB device information from sysfs
    char usb_path[512];
    char sysfs_path[512];
    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/block/%s", device);
    
    // Follow symlink to find USB device path
    char link_target[512];
    ssize_t len = readlink(sysfs_path, link_target, sizeof(link_target) - 1);
    if (len == -1) {
        printf("Unable to analyze USB device path\n");
        return;
    }
    link_target[len] = '\0';
    
    // Extract USB device information
    char *usb_pos = strstr(link_target, "usb");
    if (!usb_pos) {
        printf("Not a USB device\n");
        return;
    }
    
    // Try to find the USB device directory
    char usb_device_path[512] = {0};
    char *path_part = strtok(link_target, "/");
    char temp_path[512] = "/sys/devices";
    
    while (path_part != NULL) {
        strcat(temp_path, "/");
        strcat(temp_path, path_part);
        
        // Check if this is a USB device directory (contains idVendor and idProduct)
        char vendor_path[512];
        snprintf(vendor_path, sizeof(vendor_path), "%s/idVendor", temp_path);
        if (access(vendor_path, R_OK) == 0) {
            strcpy(usb_device_path, temp_path);
            break;
        }
        path_part = strtok(NULL, "/");
    }
    
    if (strlen(usb_device_path) == 0) {
        printf("Unable to locate USB device information\n");
        return;
    }
    
    printf("USB Device Path: %s\n", usb_device_path);
    
    // Read USB device details
    char file_path[512];
    FILE *fp;
    char buffer[256];
    
    // Vendor ID
    snprintf(file_path, sizeof(file_path), "%s/idVendor", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf("Vendor ID: %s\n", buffer);
        }
        fclose(fp);
    }
    
    // Product ID
    snprintf(file_path, sizeof(file_path), "%s/idProduct", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf("Product ID: %s\n", buffer);
        }
        fclose(fp);
    }
    
    // Manufacturer
    snprintf(file_path, sizeof(file_path), "%s/manufacturer", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf("Manufacturer: %s\n", buffer);
        }
        fclose(fp);
    }
    
    // Product name
    snprintf(file_path, sizeof(file_path), "%s/product", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf("Product: %s\n", buffer);
        }
        fclose(fp);
    }
    
    // Serial number
    snprintf(file_path, sizeof(file_path), "%s/serial", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf("Serial Number: %s\n", buffer);
        }
        fclose(fp);
    }
    
    // USB version
    snprintf(file_path, sizeof(file_path), "%s/version", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf("USB Version: %s\n", buffer);
        }
        fclose(fp);
    }
    
    // Speed
    snprintf(file_path, sizeof(file_path), "%s/speed", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf("Speed: %s Mbps\n", buffer);
        }
        fclose(fp);
    }
    
    // Device class
    snprintf(file_path, sizeof(file_path), "%s/bDeviceClass", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            int device_class = strtol(buffer, NULL, 16);
            printf("Device Class: 0x%02x ", device_class);
            switch (device_class) {
                case 0x00: printf("(Defined at Interface Level)\n"); break;
                case 0x01: printf("(Audio)\n"); break;
                case 0x02: printf("(Communications)\n"); break;
                case 0x03: printf("(HID - Human Interface Device)\n"); break;
                case 0x06: printf("(Still Image)\n"); break;
                case 0x07: printf("(Printer)\n"); break;
                case 0x08: printf("(Mass Storage)\n"); break;
                case 0x09: printf("(Hub)\n"); break;
                case 0x0A: printf("(CDC-Data)\n"); break;
                case 0x0E: printf("(Video)\n"); break;
                case 0xEF: printf("(Miscellaneous)\n"); break;
                case 0xFF: printf("(Vendor Specific)\n"); break;
                default: printf("(Unknown)\n"); break;
            }
        }
        fclose(fp);
    }
    
    // Check if it's likely a mobile phone
    analyze_mobile_device_type(usb_device_path);
}

void analyze_mobile_device_type(const char* usb_device_path) {
    printf("\n=== Mobile Device Detection ===\n");
    
    char file_path[512];
    FILE *fp;
    char buffer[256];
    
    // Read vendor and product IDs for mobile device detection
    char vendor_id[16] = {0};
    char product_id[16] = {0};
    char manufacturer[256] = {0};
    char product[256] = {0};
    
    snprintf(file_path, sizeof(file_path), "%s/idVendor", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(vendor_id, sizeof(vendor_id), fp)) {
            vendor_id[strcspn(vendor_id, "\n")] = 0;
        }
        fclose(fp);
    }
    
    snprintf(file_path, sizeof(file_path), "%s/idProduct", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(product_id, sizeof(product_id), fp)) {
            product_id[strcspn(product_id, "\n")] = 0;
        }
        fclose(fp);
    }
    
    snprintf(file_path, sizeof(file_path), "%s/manufacturer", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(manufacturer, sizeof(manufacturer), fp)) {
            manufacturer[strcspn(manufacturer, "\n")] = 0;
        }
        fclose(fp);
    }
    
    snprintf(file_path, sizeof(file_path), "%s/product", usb_device_path);
    fp = fopen(file_path, "r");
    if (fp) {
        if (fgets(product, sizeof(product), fp)) {
            product[strcspn(product, "\n")] = 0;
        }
        fclose(fp);
    }
    
    // Check for known mobile device vendors
    int is_mobile = 0;
    printf("Device Type Analysis:\n");
    
    // Common mobile device vendor IDs
    if (strcmp(vendor_id, "04e8") == 0) {
        printf("  ✓ Samsung Mobile Device Detected\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "05ac") == 0) {
        printf("  ✓ Apple Device Detected (iPhone/iPad)\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "18d1") == 0) {
        printf("  ✓ Google/Android Device Detected\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "0bb4") == 0) {
        printf("  ✓ HTC Device Detected\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "22b8") == 0) {
        printf("  ✓ Motorola Device Detected\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "0fce") == 0) {
        printf("  ✓ Sony Ericsson Device Detected\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "19d2") == 0) {
        printf("  ✓ ZTE Device Detected\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "12d1") == 0) {
        printf("  ✓ Huawei Device Detected\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "2717") == 0) {
        printf("  ✓ Xiaomi Device Detected\n");
        is_mobile = 1;
    } else if (strcmp(vendor_id, "2a70") == 0) {
        printf("  ✓ OnePlus Device Detected\n");
        is_mobile = 1;
    }
    
    // Check manufacturer and product strings for mobile indicators
    if (!is_mobile) {
        if (strstr(manufacturer, "Samsung") || strstr(manufacturer, "SAMSUNG") ||
            strstr(product, "Galaxy") || strstr(product, "GALAXY")) {
            printf("  ✓ Samsung Mobile Device (by name)\n");
            is_mobile = 1;
        } else if (strstr(manufacturer, "Apple") || strstr(product, "iPhone") || 
                   strstr(product, "iPad") || strstr(product, "iPod")) {
            printf("  ✓ Apple Mobile Device (by name)\n");
            is_mobile = 1;
        } else if (strstr(manufacturer, "Google") || strstr(product, "Android") ||
                   strstr(product, "Pixel")) {
            printf("  ✓ Android Device (by name)\n");
            is_mobile = 1;
        } else if (strstr(product, "Phone") || strstr(product, "PHONE") ||
                   strstr(product, "Mobile") || strstr(product, "MOBILE")) {
            printf("  ✓ Mobile Device (by description)\n");
            is_mobile = 1;
        }
    }
    
    if (!is_mobile) {
        printf("  - Not identified as a mobile device\n");
        printf("  - May be a USB storage device, hub, or other peripheral\n");
    } else {
        printf("\n=== Mobile Device Features ===\n");
        
        // Check for MTP (Media Transfer Protocol)
        char interface_path[512];
        snprintf(interface_path, sizeof(interface_path), "%s/*/bInterfaceClass", usb_device_path);
        
        if (system("ls /sys/bus/usb/devices/*/bInterfaceClass 2>/dev/null | head -1") == 0) {
            printf("Transfer Protocols:\n");
            
            // Check for common mobile protocols
            FILE *mtp_check = popen("lsusb -v 2>/dev/null | grep -A5 -B5 'MTP\\|PTP\\|Android\\|iPhone'", "r");
            if (mtp_check) {
                char line[512];
                int found_protocol = 0;
                while (fgets(line, sizeof(line), mtp_check)) {
                    if (strstr(line, "MTP") || strstr(line, "PTP") || 
                        strstr(line, "Android") || strstr(line, "iPhone")) {
                        printf("  %s", line);
                        found_protocol = 1;
                    }
                }
                pclose(mtp_check);
                if (!found_protocol) {
                    printf("  Standard USB protocols detected\n");
                }
            }
        }
        
        // Check for ADB (Android Debug Bridge) if available
        if (system("which adb > /dev/null 2>&1") == 0) {
            printf("\nADB Device Check:\n");
            FILE *adb_output = popen("adb devices 2>/dev/null", "r");
            if (adb_output) {
                char line[256];
                int device_found = 0;
                while (fgets(line, sizeof(line), adb_output)) {
                    if (strstr(line, "device") && !strstr(line, "List of devices")) {
                        printf("  ADB Device: %s", line);
                        device_found = 1;
                    }
                }
                pclose(adb_output);
                if (!device_found) {
                    printf("  No ADB devices detected (may need USB debugging enabled)\n");
                }
            }
        } else {
            printf("\nADB not available (install with: sudo pacman -S android-tools)\n");
        }
    }
}

void list_all_usb_devices(void) {
    printf("\n=== All Connected USB Devices ===\n");
    
    // Use lsusb if available for comprehensive USB device listing
    if (system("which lsusb > /dev/null 2>&1") == 0) {
        printf("USB Device Overview (via lsusb):\n");
        FILE *lsusb_output = popen("lsusb", "r");
        if (lsusb_output) {
            char line[512];
            while (fgets(line, sizeof(line), lsusb_output)) {
                printf("  %s", line);
            }
            pclose(lsusb_output);
        }
        printf("\n");
    }
    
    // Scan /sys/bus/usb/devices for detailed information
    printf("Detailed USB Device Analysis:\n");
    DIR *usb_dir = opendir("/sys/bus/usb/devices");
    if (usb_dir) {
        struct dirent *entry;
        int usb_count = 0;
        
        while ((entry = readdir(usb_dir)) != NULL) {
            // Skip . and .. and USB hubs (look for device entries like 1-1, 2-1.1, etc.)
            if (entry->d_name[0] == '.' || !strchr(entry->d_name, '-')) {
                continue;
            }
            
            char usb_device_path[512];
            snprintf(usb_device_path, sizeof(usb_device_path), "/sys/bus/usb/devices/%s", entry->d_name);
            
            // Check if it has idVendor (actual device, not hub/controller)
            char vendor_path[512];
            snprintf(vendor_path, sizeof(vendor_path), "%s/idVendor", usb_device_path);
            if (access(vendor_path, R_OK) != 0) {
                continue;
            }
            
            printf("\n--- USB Device %s ---\n", entry->d_name);
            usb_count++;
            
            // Read device information
            FILE *fp;
            char buffer[256];
            
            // Vendor ID
            fp = fopen(vendor_path, "r");
            if (fp) {
                if (fgets(buffer, sizeof(buffer), fp)) {
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("Vendor ID: %s\n", buffer);
                }
                fclose(fp);
            }
            
            // Product ID
            snprintf(vendor_path, sizeof(vendor_path), "%s/idProduct", usb_device_path);
            fp = fopen(vendor_path, "r");
            if (fp) {
                if (fgets(buffer, sizeof(buffer), fp)) {
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("Product ID: %s\n", buffer);
                }
                fclose(fp);
            }
            
            // Manufacturer
            snprintf(vendor_path, sizeof(vendor_path), "%s/manufacturer", usb_device_path);
            fp = fopen(vendor_path, "r");
            if (fp) {
                if (fgets(buffer, sizeof(buffer), fp)) {
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("Manufacturer: %s\n", buffer);
                }
                fclose(fp);
            }
            
            // Product
            snprintf(vendor_path, sizeof(vendor_path), "%s/product", usb_device_path);
            fp = fopen(vendor_path, "r");
            if (fp) {
                if (fgets(buffer, sizeof(buffer), fp)) {
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("Product: %s\n", buffer);
                }
                fclose(fp);
            }
            
            // Speed
            snprintf(vendor_path, sizeof(vendor_path), "%s/speed", usb_device_path);
            fp = fopen(vendor_path, "r");
            if (fp) {
                if (fgets(buffer, sizeof(buffer), fp)) {
                    buffer[strcspn(buffer, "\n")] = 0;
                    printf("Speed: %s Mbps\n", buffer);
                }
                fclose(fp);
            }
            
            // Analyze if it's a mobile device
            analyze_mobile_device_type(usb_device_path);
        }
        
        closedir(usb_dir);
        
        if (usb_count == 0) {
            printf("No USB devices found.\n");
        } else {
            printf("\nTotal USB devices analyzed: %d\n", usb_count);
        }
    } else {
        printf("Cannot access USB device information\n");
    }
}

// Parse and display NVMe security features and reserved spaces
void show_nvme_security_features(const char* device) {
    char device_path[256];
    snprintf(device_path, sizeof(device_path), "/dev/%s", device);
    printf("\n=== NVMe Security Features & Reserved Spaces ===\n");
    
    // Check if nvme-cli is available
    if (system("which nvme > /dev/null 2>&1") != 0) {
        printf("nvme-cli tool not found. Install with: sudo pacman -S nvme-cli\n");
        printf("Falling back to basic NVMe analysis...\n\n");
        
        // Try to get basic info from sysfs
        char sysfs_path[512];
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/block/%s/device", device);
        
        // Check NVMe version
        char version_path[512];
        snprintf(version_path, sizeof(version_path), "%s/firmware_rev", sysfs_path);
        FILE *fw_file = fopen(version_path, "r");
        if (fw_file) {
            char fw_rev[64];
            if (fgets(fw_rev, sizeof(fw_rev), fw_file)) {
                fw_rev[strcspn(fw_rev, "\n")] = 0;
                printf("Firmware Revision: %s\n", fw_rev);
            }
            fclose(fw_file);
        }
        
        // Check model number
        snprintf(version_path, sizeof(version_path), "%s/model", sysfs_path);
        fw_file = fopen(version_path, "r");
        if (fw_file) {
            char model[128];
            if (fgets(model, sizeof(model), fw_file)) {
                model[strcspn(model, "\n")] = 0;
                printf("Model: %s\n", model);
            }
            fclose(fw_file);
        }
        
        printf("For detailed NVMe security features, install nvme-cli package.\n");
        return;
    }
    
    // Show controller info
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "nvme id-ctrl %s 2>/dev/null", device_path);
    FILE *nvme_output = popen(cmd, "r");
    if (nvme_output) {
        char line[512];
        int found_info = 0;
        printf("NVMe Controller Information:\n");
        while (fgets(line, sizeof(line), nvme_output)) {
            if (strstr(line, "oacs") || strstr(line, "fuses") || strstr(line, "Format NVM") || 
                strstr(line, "Crypto Erase") || strstr(line, "Sanitize") || strstr(line, "firmware")) {
                printf("  %s", line);
                found_info = 1;
            }
        }
        pclose(nvme_output);
        if (!found_info) {
            printf("  Standard NVMe controller detected\n");
        }
    } else {
        printf("Unable to read NVMe controller information.\n");
    }
    
    // List namespaces
    printf("\nNVMe Namespaces:\n");
    snprintf(cmd, sizeof(cmd), "nvme list-ns %s 2>/dev/null", device_path);
    nvme_output = popen(cmd, "r");
    if (nvme_output) {
        char line[512];
        int found = 0;
        while (fgets(line, sizeof(line), nvme_output)) {
            printf("  %s", line);
            found = 1;
        }
        pclose(nvme_output);
        if (!found) {
            printf("  No additional namespaces found\n");
        }
    }
    
    // Get namespace information
    printf("\nNamespace Details:\n");
    snprintf(cmd, sizeof(cmd), "nvme id-ns %s 2>/dev/null", device_path);
    nvme_output = popen(cmd, "r");
    if (nvme_output) {
        char line[512];
        while (fgets(line, sizeof(line), nvme_output)) {
            if (strstr(line, "nsze") || strstr(line, "ncap") || strstr(line, "nuse") || 
                strstr(line, "lbaf") || strstr(line, "ms") || strstr(line, "pi")) {
                printf("  %s", line);
            }
        }
        pclose(nvme_output);
    }
    
    // Check for firmware partitions/logs
    printf("\nFirmware Log Analysis:\n");
    snprintf(cmd, sizeof(cmd), "nvme get-log %s --log-id=0x03 --log-len=512 2>/dev/null", device_path);
    nvme_output = popen(cmd, "r");
    if (nvme_output) {
        char line[512];
        int found_fw = 0;
        while (fgets(line, sizeof(line), nvme_output)) {
            if (strstr(line, "firmware") || strstr(line, "reserved") || strstr(line, "Firmware")) {
                printf("  %s", line);
                found_fw = 1;
            }
        }
        pclose(nvme_output);
        if (!found_fw) {
            printf("  No explicit firmware log entries found\n");
        }
    }
    
    // Check for security capabilities
    printf("\nSecurity Capabilities:\n");
    snprintf(cmd, sizeof(cmd), "nvme id-ctrl %s 2>/dev/null | grep -i 'security\\|sanitize\\|crypto\\|format'", device_path);
    nvme_output = popen(cmd, "r");
    if (nvme_output) {
        char line[512];
        int found_sec = 0;
        while (fgets(line, sizeof(line), nvme_output)) {
            printf("  %s", line);
            found_sec = 1;
        }
        pclose(nvme_output);
        if (!found_sec) {
            printf("  Standard security features available\n");
        }
    }
    
    printf("\nNote: Some reserved areas may not be visible without vendor-specific tools.\n");
}

// Parse and display SATA SSD security features and reserved spaces
void show_sata_security_features(const char* device) {
    char device_path[256];
    snprintf(device_path, sizeof(device_path), "/dev/%s", device);
    printf("\n=== SATA SSD Security Features & Reserved Spaces ===\n");
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "hdparm -I %s 2>/dev/null", device_path);
    FILE *hdparm_output = popen(cmd, "r");
    if (hdparm_output) {
        char line[512];
        while (fgets(line, sizeof(line), hdparm_output)) {
            if (strstr(line, "firmware") || strstr(line, "Security") || 
                strstr(line, "HPA") || strstr(line, "DCO") || strstr(line, "reserved")) {
                printf("%s", line);
            }
        }
        pclose(hdparm_output);
    } else {
        printf("hdparm not available or device not supported.\n");
    }
    
    // Show HPA/DCO info
    snprintf(cmd, sizeof(cmd), "hdparm -N %s 2>/dev/null", device_path);
    hdparm_output = popen(cmd, "r");
    if (hdparm_output) {
        char line[256];
        while (fgets(line, sizeof(line), hdparm_output)) {
            printf("%s", line);
        }
        pclose(hdparm_output);
    }
    
    snprintf(cmd, sizeof(cmd), "hdparm --dco-identify %s 2>/dev/null", device_path);
    hdparm_output = popen(cmd, "r");
    if (hdparm_output) {
        char line[256];
        while (fgets(line, sizeof(line), hdparm_output)) {
            printf("%s", line);
        }
        pclose(hdparm_output);
    }
    printf("Note: For more details, use vendor-specific tools or consult SSD documentation.\n");
}

// Detect firmware reserved spaces for SSDs (NVMe and SATA)
void check_ssd_firmware_reserved(const char* device) {
    char device_path[256];
    snprintf(device_path, sizeof(device_path), "/dev/%s", device);
    printf("\n=== SSD Firmware Reserved Space Analysis ===\n");
    
    // NVMe SSDs
    if (strncmp(device, "nvme", 4) == 0) {
        // Check if nvme-cli is available
        if (system("which nvme > /dev/null 2>&1") != 0) {
            printf("nvme-cli tool not found. Install with: sudo pacman -S nvme-cli\n");
            printf("Performing basic NVMe analysis...\n\n");
            
            // Get device size from sysfs
            char size_path[256];
            snprintf(size_path, sizeof(size_path), "/sys/block/%s/size", device);
            FILE *size_file = fopen(size_path, "r");
            if (size_file) {
                unsigned long long sectors;
                if (fscanf(size_file, "%llu", &sectors) == 1) {
                    double size_gb = (sectors * 512.0) / (1024.0 * 1024.0 * 1024.0);
                    printf("Total Capacity: %.2f GB (%llu sectors)\n", size_gb, sectors);
                }
                fclose(size_file);
            }
            
            printf("Note: For detailed firmware space analysis, install nvme-cli\n");
            return;
        }
        
        printf("Analyzing NVMe device with nvme-cli...\n");
        
        // List NVMe namespaces with detailed info
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "nvme list-ns %s 2>/dev/null", device_path);
        FILE *nvme_output = popen(cmd, "r");
        if (nvme_output) {
            char line[512];
            int found = 0;
            printf("Available Namespaces:\n");
            while (fgets(line, sizeof(line), nvme_output)) {
                printf("  %s", line);
                found = 1;
            }
            pclose(nvme_output);
            if (!found) {
                printf("  Default namespace (1) active\n");
            }
        }
        
        // Get capacity information
        printf("\nCapacity Analysis:\n");
        snprintf(cmd, sizeof(cmd), "nvme id-ns %s 2>/dev/null", device_path);
        nvme_output = popen(cmd, "r");
        if (nvme_output) {
            char line[512];
            while (fgets(line, sizeof(line), nvme_output)) {
                if (strstr(line, "nsze") || strstr(line, "ncap") || strstr(line, "nuse")) {
                    printf("  %s", line);
                }
            }
            pclose(nvme_output);
        }
        
        // Check for over-provisioning and firmware areas
        printf("\nFirmware and Reserved Areas:\n");
        snprintf(cmd, sizeof(cmd), "nvme id-ctrl %s 2>/dev/null", device_path);
        nvme_output = popen(cmd, "r");
        if (nvme_output) {
            char line[512];
            int found_fw = 0;
            while (fgets(line, sizeof(line), nvme_output)) {
                if (strstr(line, "firmware") || strstr(line, "Firmware") || 
                    strstr(line, "reserved") || strstr(line, "vendor")) {
                    printf("  %s", line);
                    found_fw = 1;
                }
            }
            pclose(nvme_output);
            if (!found_fw) {
                printf("  No explicit firmware reserved areas reported\n");
            }
        }
        
        printf("\nNote: NVMe over-provisioning and firmware areas may not be directly visible\n");
        printf("      Some reserved areas require vendor-specific tools to analyze\n");
        
    } else {
        // SATA SSDs
        printf("Analyzing SATA SSD...\n");
        
        // Check if hdparm is available
        if (system("which hdparm > /dev/null 2>&1") != 0) {
            printf("hdparm tool not found. Install with: sudo pacman -S hdparm\n");
            printf("Limited SATA analysis available...\n");
        } else {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "hdparm -I %s 2>/dev/null | grep -i 'firmware\\|reserved\\|vendor'", device_path);
            FILE *hdparm_output = popen(cmd, "r");
            if (hdparm_output) {
                char line[256];
                int found_fw = 0;
                printf("Firmware Information:\n");
                while (fgets(line, sizeof(line), hdparm_output)) {
                    printf("  %s", line);
                    found_fw = 1;
                }
                pclose(hdparm_output);
                if (!found_fw) {
                    printf("  No explicit firmware reserved info found\n");
                }
            }
        }
        
        printf("Note: SATA SSD firmware areas require vendor-specific tools for detailed analysis\n");
    }
}

void get_device_info_linux(const char* device) {
    char path[512];
    FILE *fp;
    char buffer[256];
    
    printf("=== Storage Device Information for /dev/%s ===\n", device);
    
    // Check if device is rotational (HDD vs SSD)
    snprintf(path, sizeof(path), "/sys/block/%s/queue/rotational", device);
    fp = fopen(path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            printf("Device Type: %s\n", (buffer[0] == '1') ? "HDD (Rotational)" : "SSD/Flash (Non-rotational)");
        }
        fclose(fp);
    }
    
    // Get device model
    snprintf(path, sizeof(path), "/sys/block/%s/device/model", device);
    fp = fopen(path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0; // Remove newline
            printf("Model: %s\n", buffer);
        }
        fclose(fp);
    }
    
    // Get device vendor
    snprintf(path, sizeof(path), "/sys/block/%s/device/vendor", device);
    fp = fopen(path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf("Vendor: %s\n", buffer);
        }
        fclose(fp);
    }
    
    // Get device size
    snprintf(path, sizeof(path), "/sys/block/%s/size", device);
    fp = fopen(path, "r");
    if (fp) {
        unsigned long long sectors;
        if (fscanf(fp, "%llu", &sectors) == 1) {
            double size_gb = (sectors * 512.0) / (1024.0 * 1024.0 * 1024.0);
            printf("Size: %.2f GB\n", size_gb);
        }
        fclose(fp);
    }
    
    // Get physical block size
    snprintf(path, sizeof(path), "/sys/block/%s/queue/physical_block_size", device);
    fp = fopen(path, "r");
    if (fp) {
        int block_size;
        if (fscanf(fp, "%d", &block_size) == 1) {
            printf("Physical Block Size: %d bytes\n", block_size);
        }
        fclose(fp);
    }
    
    // Get logical block size
    snprintf(path, sizeof(path), "/sys/block/%s/queue/logical_block_size", device);
    fp = fopen(path, "r");
    if (fp) {
        int block_size;
        if (fscanf(fp, "%d", &block_size) == 1) {
            printf("Logical Block Size: %d bytes\n", block_size);
        }
        fclose(fp);
    }
    
    // Check for NVMe and interface type
    snprintf(path, sizeof(path), "/sys/block/%s", device);
    char link_target[512];
    ssize_t len = readlink(path, link_target, sizeof(link_target) - 1);
    if (len != -1) {
        link_target[len] = '\0';
        if (strstr(link_target, "nvme")) {
            printf("Interface: NVMe\n");
        } else if (strstr(link_target, "ata")) {
            printf("Interface: SATA\n");
        } else if (strstr(link_target, "usb")) {
            printf("Interface: USB\n");
            printf("🔌 USB Device Detected - Performing detailed analysis...\n");
        } else if (strstr(link_target, "mmc")) {
            printf("Interface: MMC/SD\n");
        } else if (strstr(link_target, "virtio")) {
            printf("Interface: VirtIO (Virtual)\n");
        }
    }
    
    // Check removable status
    snprintf(path, sizeof(path), "/sys/block/%s/removable", device);
    fp = fopen(path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            printf("Removable: %s\n", (buffer[0] == '1') ? "Yes" : "No");
        }
        fclose(fp);
    }
    
    // Check read-only status
    snprintf(path, sizeof(path), "/sys/block/%s/ro", device);
    fp = fopen(path, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            printf("Read-Only: %s\n", (buffer[0] == '1') ? "Yes" : "No");
        }
        fclose(fp);
    }
    
    // If it's a USB device, perform detailed USB analysis
    if (len != -1 && strstr(link_target, "usb")) {
        analyze_usb_device_details(device);
    }
    
    // Add HPA/DCO, SMART, and firmware reserved checks
    printf("\n");
    check_hpa_dco_linux(device);
    check_smart_info_linux(device);
    check_ssd_firmware_reserved(device);
    
    // Show advanced security features and reserved spaces
    if (strncmp(device, "nvme", 4) == 0) {
        show_nvme_security_features(device);
    } else {
        show_sata_security_features(device);
    }
}

void get_device_info_windows() {
#ifdef _WIN32
    printf("=== Storage Device Information (Windows) ===\n");
    
    // Simple approach using basic Windows APIs
    printf("Detecting storage devices...\n");
    
    // Try to get basic drive information
    for (char drive = 'C'; drive <= 'Z'; drive++) {
        char drive_path[4] = {drive, ':', '\\', '\0'};
        UINT drive_type = GetDriveTypeA(drive_path);
        
        if (drive_type != DRIVE_NO_ROOT_DIR) {
            printf("\nDrive %c:\\\n", drive);
            
            switch (drive_type) {
                case DRIVE_FIXED:
                    printf("  Type: Fixed Drive (HDD/SSD)\n");
                    break;
                case DRIVE_REMOVABLE:
                    printf("  Type: Removable Drive\n");
                    break;
                case DRIVE_CDROM:
                    printf("  Type: CD-ROM/DVD\n");
                    break;
                case DRIVE_RAMDISK:
                    printf("  Type: RAM Disk\n");
                    break;
                case DRIVE_REMOTE:
                    printf("  Type: Network Drive\n");
                    break;
                default:
                    printf("  Type: Unknown\n");
            }
            
            // Get disk space information
            ULARGE_INTEGER free_bytes, total_bytes;
            if (GetDiskFreeSpaceExA(drive_path, &free_bytes, &total_bytes, NULL)) {
                double total_gb = total_bytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
                double free_gb = free_bytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
                printf("  Size: %.2f GB (%.2f GB free)\n", total_gb, free_gb);
            }
        }
    }
    
    printf("\nNote: For detailed hardware information on Windows, run 'wmic diskdrive list full' in Command Prompt\n");
#else
    printf("Windows-specific function called on non-Windows platform\n");
#endif
}

void list_available_devices() {
#ifdef _WIN32
    get_device_info_windows();
#else
    printf("=== Available Storage Devices ===\n");
    DIR *dir = opendir("/sys/block");
    if (dir) {
        struct dirent *entry;
        int device_count = 0;
        
        while ((entry = readdir(dir)) != NULL) {
            // Skip . and .. and loop devices, ram devices
            if (entry->d_name[0] == '.' || strncmp(entry->d_name, "loop", 4) == 0 || 
                strncmp(entry->d_name, "ram", 3) == 0 || strncmp(entry->d_name, "dm-", 3) == 0) {
                continue;
            }
            
            // Check if it's a real block device
            char path[256];
            snprintf(path, sizeof(path), "/sys/block/%s/size", entry->d_name);
            if (access(path, R_OK) == 0) {
                printf("Device: %s", entry->d_name);
                
                // Quick check for USB devices
                char usb_path[512];
                snprintf(usb_path, sizeof(usb_path), "/sys/block/%s", entry->d_name);
                char link_target[512];
                ssize_t len = readlink(usb_path, link_target, sizeof(link_target) - 1);
                if (len != -1) {
                    link_target[len] = '\0';
                    if (strstr(link_target, "usb")) {
                        printf(" [USB Device]");
                    }
                }
                printf("\n");
                
                get_device_info_linux(entry->d_name);
                printf("\n");
                device_count++;
            }
        }
        closedir(dir);
        
        if (device_count == 0) {
            printf("No storage devices found. Try running with sudo for better detection.\n");
        } else {
            printf("Total devices found: %d\n", device_count);
        }
        
        printf("\nTip: If you plug in a USB device, run this program again to detect it.\n");
        printf("     USB devices typically appear as sdb, sdc, etc. or as sd* devices.\n");
    } else {
        printf("Cannot access /sys/block directory\n");
    }
#endif
}

void print_usage(const char* program_name) {
    printf("Usage: %s [device_name] [options]\n\n", program_name);
    printf("Cross-platform Storage Device Hardware Detection Tool\n\n");
    printf("Options:\n");
    printf("  device_name    Specific device to analyze (Linux only, e.g., sda, nvme0n1)\n");
    printf("  -w, --watch    Monitor for new USB devices (Linux only)\n");
    printf("  -u, --usb      List all USB devices including mobile phones\n");
    printf("  -h, --help     Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s              # Show all storage devices\n", program_name);
    printf("  %s sda          # Show info for /dev/sda (Linux)\n", program_name);
    printf("  %s nvme0n1      # Show info for /dev/nvme0n1 (Linux)\n", program_name);
    printf("  %s --usb        # List all USB devices including mobile phones\n", program_name);
    printf("  %s --watch      # Monitor for USB device changes (Linux)\n\n", program_name);
    printf("Supported Information:\n");
    printf("  - Device Type (HDD/SSD/NVMe)\n");
    printf("  - Model and Vendor\n");
    printf("  - Storage Size\n");
    printf("  - Interface Type (SATA/NVMe/USB/etc.)\n");
    printf("  - Block Sizes\n");
    printf("  - Removable Status\n");
    printf("  - USB Device Detection\n");
    printf("  - Mobile Phone Detection (Samsung, Apple, Google, etc.)\n");
    printf("  - HPA (Host Protected Area) Detection\n");
    printf("  - DCO (Device Configuration Overlay) Detection\n");
    printf("  - Security Features Analysis\n");
    printf("  - SMART Health Status\n");
    printf("\nNote: HPA/DCO detection requires root privileges and hdparm/smartctl tools.\n");
    printf("      Mobile device analysis may require ADB for Android devices.\n");
}

void monitor_usb_devices() {
#ifndef _WIN32
    printf("=== USB Device Monitor ===\n");
    printf("Monitoring for USB storage device changes... (Press Ctrl+C to stop)\n\n");
    
    // Store initial device list
    system("ls /sys/block/ > /tmp/initial_devices.txt 2>/dev/null");
    
    while (1) {
        sleep(2); // Check every 2 seconds
        
        // Get current device list
        system("ls /sys/block/ > /tmp/current_devices.txt 2>/dev/null");
        
        // Compare with initial list
        int result = system("diff /tmp/initial_devices.txt /tmp/current_devices.txt > /dev/null 2>&1");
        
        if (result != 0) {
            printf("\n*** Device change detected! ***\n");
            system("ls /sys/block/");
            printf("\nUpdated device list:\n");
            list_available_devices();
            
            // Update initial list
            system("cp /tmp/current_devices.txt /tmp/initial_devices.txt");
            printf("\nContinuing to monitor...\n");
        }
    }
#else
    printf("USB monitoring not supported on Windows platform.\n");
    printf("Use Device Manager to monitor USB device changes.\n");
#endif
}

int main(int argc, char* argv[]) {
    printf("Hardware Storage Device Detection Tool\n");
    printf("=====================================\n\n");
    
    // Check for help flags
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 0;
    }
    
    // Check for USB devices flag
    if (argc > 1 && (strcmp(argv[1], "-u") == 0 || strcmp(argv[1], "--usb") == 0)) {
        list_all_usb_devices();
        return 0;
    }
    
    // Check for watch/monitor flag
    if (argc > 1 && (strcmp(argv[1], "-w") == 0 || strcmp(argv[1], "--watch") == 0)) {
        monitor_usb_devices();
        return 0;
    }
    
#ifdef _WIN32
    list_available_devices();
#else
    if (argc > 1) {
        // If device specified, show info for that device only
        get_device_info_linux(argv[1]);
    } else {
        // Show all available devices
        list_available_devices();
        // Also show USB devices summary
        printf("\n");
        list_all_usb_devices();
    }
#endif
    
    printf("\nNote: Some information may require elevated privileges (sudo) to access.\n");
    printf("      USB devices will be automatically detected when plugged in.\n");
    printf("      Use --usb option to see detailed USB device analysis.\n");
    return 0;
}
