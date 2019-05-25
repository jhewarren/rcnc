#include <fcntl.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <unistd.h>

using namespace std;

string getInputDeviceName() {
    int rd;
    std::string devName;
    const char* pdevsName = "/proc/bus/input/devices";

    int devsFile = open(pdevsName, O_RDONLY);
    if (devsFile == -1) {
        printf("[ERR] Open input devices file: '%s' is FAILED\n", pdevsName);
    }
    else {
        char devs[2048];

        if ((rd = read(devsFile, devs, sizeof(devs) - 1)) < 6) {
            printf("[ERR] Wrong size was read from devs file\n");
        }
        else {
            devs[rd] = 0;

            char *pHandlers, *pEV = devs;
            do {
                pHandlers = strstr(pEV, "Handlers=");
                pEV = strstr(pHandlers, "EV=");
            }
            while (pHandlers && pEV && 0 != strncmp(pEV + 3, "120013", 6));

            if (pHandlers && pEV) {
                char* pevent = strstr(pHandlers, "event");
                if (pevent) {
                    devName = string("/dev/input/event");
                    devName.push_back(pevent[5]);
                }
                else {
                    printf("[ERR] Abnormal keyboard event device\n");
                }
            }
            else {
                printf("[ERR] Keyboard event device not found\n");
            }
        }
    }

    return devName;
}