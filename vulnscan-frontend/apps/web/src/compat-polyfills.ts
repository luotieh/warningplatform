type ArrayCopyMethod = {
  <T>(this: T[]): T[];
  <T>(this: readonly T[]): T[];
};

type ArraySortCopyMethod = {
  <T>(this: T[], compareFn?: (a: T, b: T) => number): T[];
  <T>(this: readonly T[], compareFn?: (a: T, b: T) => number): T[];
};

type ArraySpliceCopyMethod = {
  <T>(this: T[], start: number, deleteCount?: number, ...items: T[]): T[];
  <T>(
    this: readonly T[],
    start: number,
    deleteCount?: number,
    ...items: T[]
  ): T[];
};

type PromiseSettledResultCompat<T> =
  | { status: 'fulfilled'; value: T }
  | { reason: unknown; status: 'rejected' };

function defineArrayMethod(name: string, value: (...args: any[]) => unknown) {
  Object.defineProperty(Array.prototype, name, {
    configurable: true,
    value,
    writable: true,
  });
}

function arrayCopy<T>(value: readonly T[]) {
  return Array.prototype.slice.call(value) as T[];
}

if (!Array.prototype.toReversed) {
  defineArrayMethod('toReversed', function toReversed<T>(this: readonly T[]) {
    return arrayCopy(this).reverse();
  } satisfies ArrayCopyMethod);
}

if (!Array.prototype.toSorted) {
  defineArrayMethod('toSorted', function toSorted<T>(
    this: readonly T[],
    compareFn?: (a: T, b: T) => number,
  ) {
    return arrayCopy(this).sort(compareFn);
  } satisfies ArraySortCopyMethod);
}

if (!Array.prototype.toSpliced) {
  defineArrayMethod('toSpliced', function toSpliced<T>(
    this: readonly T[],
    start: number,
    deleteCount?: number,
    ...items: T[]
  ) {
    const copy = arrayCopy(this);
    if (deleteCount === undefined) {
      copy.splice(start);
    } else {
      copy.splice(start, deleteCount, ...items);
    }
    return copy;
  } satisfies ArraySpliceCopyMethod);
}

if (!Array.prototype.with) {
  defineArrayMethod('with', function withAt<T>(
    this: T[],
    index: number,
    value: T,
  ) {
    const copy = arrayCopy(this);
    const actualIndex = index < 0 ? copy.length + index : index;
    if (actualIndex < 0 || actualIndex >= copy.length) {
      throw new RangeError('Invalid index');
    }
    copy[actualIndex] = value;
    return copy;
  });
}

if (!Promise.allSettled) {
  Promise.allSettled = function allSettled<T>(
    values: Iterable<T | PromiseLike<T>>,
  ): Promise<Array<PromiseSettledResultCompat<Awaited<T>>>> {
    return Promise.all(
      Array.from(values, (value) =>
        Promise.resolve(value).then(
          (resolved) => ({
            status: 'fulfilled' as const,
            value: resolved as Awaited<T>,
          }),
          (reason) => ({ reason, status: 'rejected' as const }),
        ),
      ),
    );
  };
}

if (!Object.fromEntries) {
  Object.fromEntries = function fromEntries(
    entries: Iterable<readonly [PropertyKey, unknown]>,
  ) {
    const result: Record<PropertyKey, unknown> = {};
    for (const [key, value] of entries) {
      result[key] = value;
    }
    return result;
  };
}

if (typeof crypto !== 'undefined' && !crypto.randomUUID) {
  Object.defineProperty(crypto, 'randomUUID', {
    configurable: true,
    value() {
      const bytes = new Uint8Array(16);
      if (crypto.getRandomValues) {
        crypto.getRandomValues(bytes);
      } else {
        for (let i = 0; i < bytes.length; i += 1) {
          bytes[i] = Math.floor(Math.random() * 256);
        }
      }
      bytes[6] = (bytes[6]! & 0x0f) | 0x40;
      bytes[8] = (bytes[8]! & 0x3f) | 0x80;
      const hex = Array.from(bytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
      );
      return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex
        .slice(6, 8)
        .join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10).join('')}`;
    },
    writable: true,
  });
}
