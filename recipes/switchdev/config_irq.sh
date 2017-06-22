#!/bin/bash

devname=$1

bus_info=$(ethtool -i $devname|grep bus-info|awk -F": " '{print $2}')
echo "devname: $devname"
echo "bus_info: $bus_info"

#systemctl enable cpupower.service
systemctl stop irqbalance
#ethtool -K $devname  gro on gso on tso on tx on rx on

irqs=$(cat /proc/interrupts | grep "$bus_info" | awk '{print $1}' | tr -d :)
if [ -z "$irqs" ];then
	irqs=$(cat /proc/interrupts | grep "$devname" | awk '{print $1}' | tr -d :)
fi
irq_count=$(echo $irqs|wc -w)
process_count=$(cat /proc/cpuinfo |grep processor|wc -l)

echo "irqs= $irqs"
echo "irq_count= $irq_count"
echo "process_count = $process_count"

irq_index=0
for irq in $irqs; 
do 
	case $irq_index in
		0|1|2) 
			echo 0-5,12-17 > /proc/irq/$irq/smp_affinity_list
		;;
		*)
			cpu=$((($irq_index-3)%$process_count)) 
			echo $cpu > /proc/irq/$irq/smp_affinity_list
		;;
	esac
        let irq_index++
done

for irq in $irqs; 
do 
	cat /proc/irq/$irq/smp_affinity_list ; 
done
