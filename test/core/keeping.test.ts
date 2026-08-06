import libsodium from 'libsodium-wrappers-sumo';
import { assert, describe, it } from 'vitest';
import { Diger, MtrDex, Salter, Tier } from '../../src';
import { SaltyKeeper } from '../../src/keri/core/keeping';
import { b } from '../../src/keri/core/core';

/**
 * Pre-rotation publishes a digest of the next key, never the key. A caller that
 * has to commit to it in a form KERI does not publish, a Cardano key hash for
 * one, cannot work from the digest and would otherwise reimplement the index
 * arithmetic incept and rotate use. A copy that drifts commits to a key nobody
 * holds, and that is only discovered at the rotation it blocks.
 */

describe('SaltyKeeper next keys', () => {
    const newManager = () =>
        new SaltyKeeper(
            new Salter({ raw: b('0123456789abcdef') }),
            0,
            0,
            Tier.low,
            true
        );

    it('returns the key the next rotation goes on to reveal', async () => {
        await libsodium.ready;

        const manager = newManager();
        await manager.incept(true);
        const predicted = manager.nextVerfers().map((v) => v.qb64);

        const [revealed] = await manager.rotate([MtrDex.Ed25519_Seed], true);
        assert.deepEqual(revealed, predicted);
    });

    it('still does, one rotation later', async () => {
        await libsodium.ready;

        const manager = newManager();
        await manager.incept(true);
        await manager.rotate([MtrDex.Ed25519_Seed], true);

        const predicted = manager.nextVerfers().map((v) => v.qb64);
        const [revealed] = await manager.rotate([MtrDex.Ed25519_Seed], true);
        assert.deepEqual(revealed, predicted);
    });

    it('agrees with the digest incept published, which is the same derivation', async () => {
        await libsodium.ready;

        const manager = newManager();
        const [, digers] = await manager.incept(true);
        const fromKeys = manager
            .nextVerfers()
            .map((v) => new Diger({ code: MtrDex.Blake3_256 }, v.qb64b).qb64);

        assert.deepEqual(fromKeys, digers);
    });

    it('is not the current key, or pre-rotation would be pointless', async () => {
        await libsodium.ready;

        const manager = newManager();
        const [verfers] = await manager.incept(true);
        const next = manager.nextVerfers().map((v) => v.qb64);

        assert.notDeepEqual(next, verfers);
    });

    it('is stable across calls, since it is derived and not drawn', async () => {
        await libsodium.ready;

        const manager = newManager();
        await manager.incept(true);
        assert.deepEqual(
            manager.nextVerfers().map((v) => v.qb64),
            manager.nextVerfers().map((v) => v.qb64)
        );
    });
});
