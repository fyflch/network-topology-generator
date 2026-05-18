/**
 * 测试 LLDP SNMP 解析逻辑（模拟 server.js 中的 snmpGetLLDPNeighbors）
 */
const snmp = require('net-snmp');

const TARGET = '172.16.16.2';
const COMMUNITY = 'public';

const base = '1.0.8802.1.1.2.1.4.1.1';
const BASE_LEN = (base + '.X').split('.').length; // 12

const fields = [
  { name: 'chassisId',  oid: base + '.5' },
  { name: 'portId',     oid: base + '.7' },
  { name: 'portDesc',   oid: base + '.8' },
  { name: 'sysName',    oid: base + '.9' },
  { name: 'sysDesc',    oid: base + '.10' },
  { name: 'localPort',  oid: base + '.3' },
];

const session = snmp.createSession(TARGET, COMMUNITY, {
  timeout: 8000, retries: 1, version: snmp.Version2c
});

const neighborMap = {};
let completed = 0;

fields.forEach((field) => {
  session.subtree(field.oid, 20, (varbinds) => {
    for (const vb of varbinds) {
    if (!vb || snmp.isVarbindError(vb)) continue;
    const oidParts = vb.oid.split('.');
    const afterBase = oidParts.slice(BASE_LEN);
    if (afterBase.length < 2) return;
    const localPortNum = afterBase[afterBase.length - 2];
    const remoteIdx   = afterBase[afterBase.length - 1];
    const key = `${localPortNum}.${remoteIdx}`;
    if (!neighborMap[key]) {
      neighborMap[key] = { _idx: key, _localIfIdx: localPortNum };
    }
    let val = '';
    if (Buffer.isBuffer(vb.value)) {
      const s = vb.value.toString('utf8').replace(/[\x00-\x1F\x7F]/g, '');
      val = s.length > 0 ? s : vb.value.toString('hex');
    } else {
      val = vb.value != null ? String(vb.value).trim() : '';
    }
    neighborMap[key][field.name] = val;
    } // end for varbinds
  }, (err) => {
    if (err) console.log(`[WARN] ${field.name}: ${err.message}`);
    completed++;
    if (completed === fields.length) {
      session.close();
      console.log('\n=== 解析到的 LLDP 邻居 ===\n');
      for (const key of Object.keys(neighborMap)) {
        const n = neighborMap[key];
        console.log(`--- 邻居 key=${key} ---`);
        console.log(`  本地端口索引: ${n._localIfIdx}`);
        console.log(`  localPort:    ${n.localPort || '(空)'}`);
        console.log(`  sysName:      ${n.sysName   || '(空)'}`);
        console.log(`  portId:       ${n.portId    || '(空)'}`);
        console.log(`  portDesc:     ${n.portDesc  || '(空)'}`);
        console.log(`  chassisId:    ${n.chassisId || '(空)'}`);
        console.log('');
      }
      console.log(`共发现 ${Object.keys(neighborMap).length} 个邻居`);
    }
  });
});
