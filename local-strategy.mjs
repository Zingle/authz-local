import CIDR from "ip-cidr";
import custom from "passport-custom";

const {Strategy} = custom;
const IPv4_SUBNET = "::ffff:";

/**
 * Create local network authentication strategy.
 * @param {string} [network]
 * @returns {function}
 */
export default function localStrategy(network="127.0.0.0/8 ::1/128") {
    const networks = network.split(" ").map(network => new CIDR(network));

    return new Strategy(verify);

    function verify(req, done) {
        const ip = decodeIPv6(req.connection.remoteAddress);

        if (networks.some(network => network.contains(ip))) {
            const user = {local: {ip}};
            done(null, user);
        } else {
            done(null, false);
        }
    }
}

/**
 * Decode IPv4 address embedded into IPv6 address or return the address as
 * provided.
 * @param {string} ip
 * @returns {string}
 */
function decodeIPv6(ip) {
    return ip.startsWith(IPv4_SUBNET) ? ip.slice(IPv4_SUBNET.length) : ip;
}
