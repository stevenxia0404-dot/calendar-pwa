// 记录 ID 生成 —— 单元测试
//
// 这个模块存在的唯一原因：crypto.randomUUID() 在非安全上下文里不存在。
// 通过内网 IP 访问时点「记下来」会抛 TypeError，整个输入功能不可用。
// 所以这里锁死降级行为，防止将来有人改回直接调 crypto.randomUUID()。

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { newId } from '../src/lib/id.ts';

describe('newId —— 安全上下文（正常路径）', () => {
  test('1. 生成合法 UUID v4 格式', () => {
    const id = newId();
    assert.match(
      id,
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      `不是 UUID v4：${id}`,
    );
  });

  test('2. 连续调用不重复', () => {
    const set = new Set<string>();
    for (let i = 0; i < 5000; i++) set.add(newId());
    assert.equal(set.size, 5000, '出现了重复 id');
  });
});

describe('newId —— 非安全上下文（降级路径）', () => {
  // 模拟「通过内网 IP 访问」：crypto.randomUUID 不存在，
  // 但 crypto.getRandomValues 存在（浏览器里就是这样）。
  const original = globalThis.crypto;

  // globalThis.crypto 是只读 getter，不能直接赋值 —— 用 defineProperty 覆盖。
  function setCrypto(value: Crypto | undefined) {
    Object.defineProperty(globalThis, 'crypto', {
      value,
      configurable: true,
      writable: true,
    });
  }

  function restoreCrypto() {
    Object.defineProperty(globalThis, 'crypto', {
      value: original,
      configurable: true,
      writable: true,
    });
  }

  test('3. randomUUID 缺失时降级到 getRandomValues，仍是合法 UUID v4', () => {
    setCrypto({
      getRandomValues: original.getRandomValues.bind(original),
    } as Crypto);

    try {
      const id = newId();
      assert.match(
        id,
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
        `降级后不是 UUID v4：${id}`,
      );
    } finally {
      restoreCrypto();
    }
  });

  test('4. 降级路径连发 5000 次仍不重复', () => {
    setCrypto({
      getRandomValues: original.getRandomValues.bind(original),
    } as Crypto);

    try {
      const set = new Set<string>();
      for (let i = 0; i < 5000; i++) set.add(newId());
      assert.equal(set.size, 5000, '降级路径出现重复 id');
    } finally {
      restoreCrypto();
    }
  });

  test('5. 连 crypto 都没有时也不抛异常（最老浏览器兜底）', () => {
    setCrypto(undefined as unknown as Crypto);

    try {
      const id = newId();
      assert.ok(typeof id === 'string' && id.length > 0, '兜底路径没有返回字符串');
      const set = new Set<string>();
      for (let i = 0; i < 5000; i++) set.add(newId());
      assert.equal(set.size, 5000, '兜底路径出现重复 id');
    } finally {
      restoreCrypto();
    }
  });

  test('6. 兜底路径的 id 仍可用作后端主键（不含非法字符）', () => {
    setCrypto(undefined as unknown as Crypto);

    try {
      const id = newId();
      assert.match(id, /^[A-Za-z0-9-]+$/, `id 含后端不接受的字符：${id}`);
    } finally {
      restoreCrypto();
    }
  });
});
