#!/bin/sh
echo 1 > /sys/devices/system/cpu/cpu0/online
echo 1 > /sys/devices/system/cpu/cpu1/online
echo 1 > /sys/devices/system/cpu/cpu2/online
echo 1 > /sys/devices/system/cpu/cpu3/online
echo performance > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
echo performance > /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor
echo performance > /sys/devices/system/cpu/cpu2/cpufreq/scaling_governor
echo performance > /sys/devices/system/cpu/cpu3/cpufreq/scaling_governor
echo 8388608 > /proc/sys/net/core/wmem_default
echo 8388608 > /proc/sys/net/core/rmem_default
echo 8388608 > /proc/sys/net/core/wmem_max
echo 8388608 > /proc/sys/net/core/rmem_max
echo 3300000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq
echo 3300000 > /sys/devices/system/cpu/cpu1/cpufreq/scaling_min_freq
echo 3300000 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_min_freq
echo 3300000 > /sys/devices/system/cpu/cpu3/cpufreq/scaling_min_freq
