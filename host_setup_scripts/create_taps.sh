# source this script! all TAP interface names need to be available to VM startup scripts

if [[ $(id -u) != 0 ]]; then
	echo "Must be root."
	exit 1
fi

# set as environment variables so they're available in VM startup scripts too
# these are taps, one for each endpoint (and fw gets 2 taps since its connected to two networks)
export INT_HOST_TAP="int_host_tap"
export EXT_HOST_TAP="ext_host_tap"
export INT_FW_TAP="int_fw_tap"
export EXT_FW_TAP="ext_fw_tap"

INT_BRIDGE_NAME="int_net_br"
EXT_BRIDGE_NAME="ext_net_br"

TAPS=($INT_HOST_TAP $EXT_HOST_TAP $INT_FW_TAP $EXT_FW_TAP)
BRIDGES=($INT_BRIDGE_NAME $EXT_BRIDGE_NAME)

for tap_name in "${TAPS[@]}"; do
	ip tuntap add dev $tap_name mode tap
done

for bridge_name in "${BRIDGES[@]}"; do
	ip link add name $bridge_name type bridge
done

ip link set dev $INT_HOST_TAP master $INT_BRIDGE_NAME
ip link set dev $INT_FW_TAP master $INT_BRIDGE_NAME
ip link set dev $EXT_HOST_TAP master $EXT_BRIDGE_NAME
ip link set dev $EXT_FW_TAP master $EXT_BRIDGE_NAME

for dev in "${BRIDGES[@]}" "${TAPS[@]}"; do
	ip link set dev $dev up
done
