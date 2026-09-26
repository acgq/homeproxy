#!/usr/bin/ucode

'use strict';

import { writefile } from 'fs';
import { cursor } from 'uci';
import { isEmpty, RUN_DIR } from 'homeproxy';

const cfgname = 'homeproxy';
const uci = cursor();
uci.load(cfgname);

const routing_mode = uci.get(cfgname, 'config', 'routing_mode') || 'bypass_mainland_china',
      proxy_mode = uci.get(cfgname, 'config', 'proxy_mode') || 'redirect_tproxy';

let outbound_node, tun_name;
if (match(proxy_mode, /tun/)) {
	if (routing_mode === 'custom')
		outbound_node = uci.get(cfgname, 'routing', 'default_outbound') || 'nil';
	else
		outbound_node = uci.get(cfgname, 'config', 'main_node') || 'nil';

	if (outbound_node !== 'nil')
		tun_name = uci.get(cfgname, 'infra', 'tun_name') || 'singtun0';
}

const server_enabled = uci.get(cfgname, 'server', 'enabled');

let forward = [],
    input = [];

if (tun_name) {
	push(forward, `oifname ${tun_name} counter accept comment "!${cfgname}: accept tun forward"`);
	push(input ,`iifname ${tun_name} counter accept comment "!${cfgname}: accept tun input"`);
}

if (server_enabled === '1') {
	uci.foreach(cfgname, 'server', (s) => {
		if (s.enabled !== '1' || s.firewall !== '1')
			return;

		let proto = s.type === 'queqiao'
			? (s.queqiao_transport === 'tcp' ? 'tcp' : s.queqiao_transport === 'quic' ? 'udp' : '{ tcp, udp }')
			: (s.network || '{ tcp, udp }');
		push(input, `meta l4proto ${proto} th dport ${s.port} counter accept comment "!${cfgname}: accept server ${s['.name']}"`);
		if (s.type === 'queqiao' && s.queqiao_transport !== 'tcp') {
			for (let port of (s.queqiao_hop_ports || [])) {
				let parts = split(port, ':');
				if (length(parts) > 2 || !match(parts[0], /^[0-9]+$/) ||
					(length(parts) === 2 && !match(parts[1], /^[0-9]+$/)))
					continue;
				let first = +parts[0], last = +(parts[1] || parts[0]);
				if (first < 1 || last > 65535 || first > last)
					continue;
				push(input, `udp dport { ${first}${first === last ? '' : '-' + last} } counter accept comment "!${cfgname}: accept queqiao hops ${s['.name']}"`);
			}
		}
	});
}

if (!isEmpty(forward))
	writefile(RUN_DIR + '/fw4_forward.nft', join('\n', forward) + '\n');

if (!isEmpty(input))
	writefile(RUN_DIR + '/fw4_input.nft', join('\n', input) + '\n');
