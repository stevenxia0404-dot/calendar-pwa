// 生成记录 ID
//
// 为什么不用 crypto.randomUUID()：
// 该 API 只在「安全上下文」里可用 —— HTTPS，或 localhost。
// 通过内网 IP 访问（http://192.168.x.x）时不在安全上下文，
// crypto.randomUUID 直接不存在，点「记下来」就抛 TypeError。
//
// 这个产品会被这样访问：
//   - 局域网 IP（家里 WiFi、办公室内网）
//   - 内网部署的 Worker（自建服务器，非 https）
//   - 部分微信/企业 App 内置浏览器
// 这些场景下用户点一下「记下来」就整个不能用 —— 不能接受。
//
// 所以这里做降级：优先用 randomUUID，没有就用 getRandomValues，
// 再没有就退回时间戳 + 随机数（仍然是低碰撞，够用）。
//
// 唯一性要求只是「不同记录 id 不撞」，不是密码学安全，
// 因此降级路径用 Math.random() 完全可以接受。

/** 生成一个 UUID v4 格式的字符串 */
export function newId(): string {
  // 1) 标准路径：安全上下文
  const c = globalThis.crypto as Crypto | undefined;
  if (c && typeof c.randomUUID === 'function') {
    return c.randomUUID();
  }

  // 2) 降级路径：getRandomValues（非安全上下文也存在）
  if (c && typeof c.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    // 置位：version=4，variant=10xx
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex: string[] = [];
    for (let i = 0; i < 16; i++) hex.push(bytes[i].toString(16).padStart(2, '0'));
    return (
      hex.slice(0, 4).join('') + '-' +
      hex.slice(4, 6).join('') + '-' +
      hex.slice(6, 8).join('') + '-' +
      hex.slice(8, 10).join('') + '-' +
      hex.slice(10, 16).join('')
    );
  }

  // 3) 最后兜底：没有 crypto 时的老浏览器。
  //    时间戳保证单调递增，随机后缀避免同一毫秒内碰撞。
  const ts = Date.now().toString(36);
  const rand = Math.floor(Math.random() * 0x100000000).toString(36);
  return `${ts}-${rand}`;
}
