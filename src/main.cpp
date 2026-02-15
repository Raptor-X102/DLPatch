#include "plugin_manager.h"
#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>

PluginManager g_pm;
volatile bool running = true;

void signalHandler(int s) {
    if (s == SIGUSR1) {
        std::cout << "\nReloading plugin...\n";
        g_pm.loadPlugin("./libmy_new_plugin.so"); // или путь к новому модулю
    } else {
        running = false;
    }
}

int main() {
    signal(SIGINT, signalHandler);
    signal(SIGUSR1, signalHandler);

    if (!g_pm.loadPlugin("./libmy_plugin.so")) {
        std::cerr << "Failed to load plugin.\n";
        return -1;
    }

    std::cout << "PID: " << getpid() << std::endl;
    std::cout << "Send SIGUSR1 to reload plugin:\n";
    std::cout << "kill -SIGUSR1 " << getpid() << std::endl;

    while (running) {
        g_pm.usePlugin();

        // Получаем функцию по имени
        auto func = (double (*)(double, double))g_pm.getFunction("add");
        if (func) {
            std::cout << "add(10, 5) = " << func(10, 5) << std::endl;
        }

        g_pm.releasePlugin();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    return 0;
}
