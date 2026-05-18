'use strict';
const snmp = require('net-snmp');

const HOSTS = [
  { ip: '172.16.16.2',   name: '2FRDJHLW1' },
  { ip: '172.16.16.7',   name: '7FRDJHLW' },
  { ip: '172.16.16.51',  name: '5FRDJHLW' },
  { ip: '172.16.16.52',  name: '5FZHZXHLW' },
  { ip: '172.16.16.254', name: 'JZFJ-NEW-HLWHX' },
];
const COMMUNITY = 'public';

// LLDP-MIB OIDs
const LLDP_BASE = '1.0.8802.1.1.2.1.4.1.1';
const LLDP_OIDS = {
  localPort: LLDP_BASE + '.3',
  chassisId: LLDP_BASE + '.5',
  portId:    LLDP_BASE + '.7',
  portDesc:  LLDP_BASE + '.8',
  sysName:   LLDP_BASE + '.9',
};

function snmpWalk(host, oid, timeout) {
  return new Promise((resolve) => {
    const results = {};
    const session = snmp.createSession(host, COMMUNITY, {
      timeout: timeout || 5000, retries: 1, version: snmp.Version2c
    });
    const safetyTimer = setTimeout(() => {
      try { session.close(); } catch(_) {}
      resolve(results);
    }, (timeout || 5000) + 2000);

    session.walk(oid, 20, (vb) => {
      if (!vb || !vb.value) return;
      results[vb.oid] = vb.value.toString();
    }, (err) => {
      clearTimeout(safetyTimer);
      try { session.close(); } catch(_) {}
      resolve(results);
    });
  });
}

async function getLLDPNeighbors(host) {
  const [localPorts, chassisIds, portIds, portDescs, sysNames] = await Promise.all([
    snmpWalk(host, LLDP_OIDS.localPort, 6000),
    snmpWalk(host, LLDP_OIDS.chassisId, 6000),
    snmpWalk(host, LLDP_OIDS.portId,    6000),
    snmpWalk(host, LLDP_OIDS.portDesc,  6000),
    snmpWalk(host, LLDP_OIDS.sysName,   6000),
  ]);

  // 以 chassisIds 的 key 为主索引
  const map = {};
  for (const oid of Object.keys(chassisIds)) {
    const suffix = oid.replace(LLDP_OIDS.chassisId + '.', '');
    const localOid = LLDP_OIDS.localPort + '.' + suffix;
    map[suffix] = {
      localPort: localPorts[localOid]  || suffix.split('.')[0] || '?',
      chassisId: chassisIds[oid]       || '',
      portId:    portIds[LLDP_OIDS.portId + '.' + suffix]    || '',
      portDesc:  portDescs[LLDP_OIDS.portDesc + '.' + suffix] || '',
      sysName:   sysNames[LLDP_OIDS.sysName + '.' + suffix]  || '',
    };
  }
  return Object.values(map);
}

// 也测试一下 SNMP sysName 是否通
async function snmpGet(host, oid) {
  return new Promise((resolve) => {
    const s = snmp.createSession(host, COMMUNITY, { timeout: 4000, retries: 1, version: snmp.Version2c });
    s.get([oid], (err, vbs) => {
      s.close();
      if (err || !vbs.length) resolve(null);
      else resolve(vbs[0].value ? vbs[0].value.toString() : null);
    });
  });
}

(async () => {
  console.log('=== SNMP LLDP 专项测试 ===\n');

  for (const h of HOSTS) {
    console.log(`\n── ${h.name} (${h.ip}) ──`);

    // 先测 sysName 通不通
    const sysName = await snmpGet(h.ip, '1.3.6.1.2.1.1.5.0');
    console.log(`  SNMP sysName: ${sysName || '❌ 无响应'}`);

    if (!sysName) {
      console.log('  SNMP不通，跳过LLDP');
      continue;
    }

    // 获取 LLDP 邻居
    const neighbors = await getLLDPNeighbors(h.ip);
    console.log(`  LLDP 邻居数: ${neighbors.length}`);
    if (neighbors.length > 0) {
      neighbors.forEach((n, i) => {
        console.log(`    [${i+1}] localPort=${n.localPort}  sysName=${n.sysName}  chassisId=${n.chassisId}  portId=${n.portId}`);
      });
    } else {
      console.log('  ⚠️  LLDP 邻居为空（设备可能未开启LLDP，或SNMP没有LLDP-MIB访问权限）');
      // 额外检查: lldpLocalSystemData
      const lldpCap = await snmpGet(h.ip, '1.0.8802.1.1.2.1.3.0');
      console.log('  lldpLocalCap OID(1.0.8802.1.1.2.1.3.0):', lldpCap || '无');
      const lldpSysDesc = await snmpGet(h.ip, '1.0.8802.1.1.2.1.3.3.0');
      console.log('  lldpLocSysDesc:', lldpSysDesc || '无');
    }
  }
  console.log('\n=== 测试完毕 ===');
  process.exit(0);
})();
