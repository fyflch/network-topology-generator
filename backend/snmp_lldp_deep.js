/**
 * 深度测试 LLDP SNMP OID
 * 锐捷设备可能用私有 OID 或不同的标准 OID 路径
 */
const snmp = require('net-snmp');

const TARGET = '172.16.16.2';
const COMMUNITY = 'public';

const session = snmp.createSession(TARGET, COMMUNITY, {
  version: snmp.Version2c,
  timeout: 5000,
  retries: 2
});

// 各种 LLDP 相关 OID 路径
const OID_SETS = [
  // 标准 LLDP MIB (IEEE 802.1AB)
  { name: 'lldpLocalPortTable', oid: '1.0.8802.1.1.2.1.3.7' },
  { name: 'lldpRemTable', oid: '1.0.8802.1.1.2.1.4.1' },
  { name: 'lldpRemSysName', oid: '1.0.8802.1.1.2.1.4.1.1.9' },
  { name: 'lldpRemChassisId', oid: '1.0.8802.1.1.2.1.4.1.1.5' },
  { name: 'lldpRemPortId', oid: '1.0.8802.1.1.2.1.4.1.1.7' },
  { name: 'lldpStatsTxTable', oid: '1.0.8802.1.1.2.1.2.6' },
  
  // 另一种标准 OID 格式（有些设备用这个）
  { name: 'lldpRemTable-alt', oid: '1.3.111.2.802.1.1.2.1.4.1' },
  { name: 'lldpRemSysName-alt', oid: '1.3.111.2.802.1.1.2.1.4.1.1.9' },
  
  // 锐捷私有 LLDP OID
  { name: 'ruijie-lldp', oid: '1.3.6.1.4.1.4881.1.1.4.7.1' },
  { name: 'ruijie-lldp2', oid: '1.3.6.1.4.1.4881.1.1.4.7' },
  
  // CDP (某些设备用)
  { name: 'cdpCacheTable', oid: '1.3.6.1.4.1.9.9.23.1.2.1' },
];

async function walkOid(name, oid) {
  return new Promise((resolve) => {
    const results = [];
    session.subtree(oid, 20, 
      (varbinds) => {
        for (const v of varbinds) {
          if (snmp.isVarbindError(v)) continue;
          let val = v.value;
          if (Buffer.isBuffer(val)) {
            // 尝试打印为字符串
            const str = val.toString('utf8').replace(/[^\x20-\x7E]/g, '.');
            val = `hex:${val.toString('hex')} str:"${str}"`;
          }
          results.push(`  ${v.oid} = ${val}`);
        }
      },
      (err) => {
        if (err) {
          resolve({ name, oid, count: 0, error: err.message });
        } else {
          resolve({ name, oid, count: results.length, data: results.slice(0, 10) });
        }
      }
    );
  });
}

async function main() {
  console.log(`\n=== 深度 LLDP SNMP 测试 ${TARGET} ===\n`);
  
  for (const { name, oid } of OID_SETS) {
    const result = await walkOid(name, oid);
    if (result.error) {
      console.log(`[${name}] ${oid} → ERROR: ${result.error}`);
    } else if (result.count === 0) {
      console.log(`[${name}] ${oid} → 空 (0条)`);
    } else {
      console.log(`[${name}] ${oid} → ✅ ${result.count} 条:`);
      result.data.forEach(d => console.log(d));
    }
    console.log('');
  }
  
  // 额外：直接 GET lldpStatsRemTablesInserts 看有没有统计
  const statsOids = [
    '1.0.8802.1.1.2.1.2.1.0',  // lldpStatsRemTablesInserts
    '1.0.8802.1.1.2.1.2.2.0',  // lldpStatsRemTablesDeletes
    '1.0.8802.1.1.2.1.2.3.0',  // lldpStatsRemTablesDrops
    '1.0.8802.1.1.2.1.1.1.0',  // lldpMessageTxInterval
  ];
  
  console.log('=== LLDP 统计指标 ===');
  await new Promise((resolve) => {
    session.get(statsOids, (err, varbinds) => {
      if (err) {
        console.log('GET error:', err.message);
      } else {
        for (const v of varbinds) {
          if (snmp.isVarbindError(v)) {
            console.log(`  ${v.oid} = ERROR: ${snmp.varbindError(v).message}`);
          } else {
            console.log(`  ${v.oid} = ${v.value}`);
          }
        }
      }
      resolve();
    });
  });
  
  session.close();
}

main().catch(console.error);
