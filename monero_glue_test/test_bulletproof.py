#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
from binascii import unhexlify
import unittest

import aiounittest
from monero_serialize.xmrtypes import Bulletproof

from monero_glue.xmr import crypto
from monero_glue.xmr import bulletproof as bp


class BulletproofTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(BulletproofTest, self).__init__(*args, **kwargs)

    def can_test(self):
        return crypto.get_backend().has_crypto_into_functions()

    def skip_if_cannot_test(self):
        if not self.can_test():
            self.skipTest("Crypto backend does not implement required functions")

    def test_constants(self):
        """
        Bulletproof constants testing
        :return:
        """
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        Gi, Hi = bp.init_exponents()
        res = bp.init_constants()

    def mask_consistency_check(self, bpi):
        self.assertEqual(bpi.sL(0), bpi.sL(0))
        self.assertEqual(bpi.sL(1), bpi.sL(1))
        self.assertEqual(bpi.sL(63), bpi.sL(63))
        self.assertNotEqual(bpi.sL(1), bpi.sL(0))

        self.assertEqual(bpi.sR(0), bpi.sR(0))
        self.assertEqual(bpi.sR(1), bpi.sR(1))
        self.assertEqual(bpi.sR(63), bpi.sR(63))
        self.assertNotEqual(bpi.sR(1), bpi.sR(0))

        self.assertNotEqual(bpi.sL(0), bpi.sR(0))
        self.assertNotEqual(bpi.sL(1), bpi.sR(1))
        self.assertNotEqual(bpi.sL(63), bpi.sR(63))

        bpi.init_vct()
        ve1 = bp._ensure_dst_key()
        ve2 = bp._ensure_dst_key()
        bpi.vector_exponent(bpi.v_aL, bpi.v_aR, ve1)
        bpi.vector_exponent(bpi.v_aL, bpi.v_aR, ve2)

        bpi.vector_exponent(bpi.v_sL, bpi.v_sR, ve1)
        bpi.vector_exponent(bpi.v_sL, bpi.v_sR, ve2)
        self.assertEqual(ve1, ve2)

    def test_masks(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        val = crypto.sc_init(123)
        mask = crypto.sc_init(432)
        bpi.set_input(val, mask)
        self.mask_consistency_check(bpi)

        # Randomized masks
        bpi.use_det_masks = False
        self.mask_consistency_check(bpi)

    def test_verify(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()

        # fmt: off
        bp_proof = Bulletproof(
            V=[
                unhexlify(b"3c705e1da4bbe43a0535a5ad3a8e6c148fb8c1a4118ba6b65412b2fe6511b261"),
            ],
            A=unhexlify(b"d5eabb643dd389feb0d2fcf52b1724366857f9d3a788bc3c98c4ed7da4772788"),
            S=unhexlify(b"9e1409aefd7894b32ba653907ff5629be9cb5e7ab0203f867fad75ea9268aeec"),
            T1=unhexlify(b"207abb3a93240122aeb2c7608f21070be50fbd6338fc9d377bfa54920ebc6be3"),
            T2=unhexlify(b"360fbb7236933727cffa1cc890411149bea901912d74466d2d78626278fdc697"),
            taux=unhexlify(b"1eda60245329ff5e061d0b4d08233c404ac51d0789e36fdf6e1192e771e34603"),
            mu=unhexlify(b"2b7e632f9e94e9a8cd530d46077dfc3bdac54b4a6d4be51b37a280df966f3701"),
            L=[unhexlify(b"51d445445d09f4ac601cd17a9111ffa05cd4811fe41752a12282d2346ac215e7"),
               unhexlify(b"72e80df9c13b59be50a4088da56e38251f2c9865643fa5a4cb6373570f95b508"),
               unhexlify(b"bcff821f5545cbbe6433cc198979c81fdb2bd60cd0703e382fb20a68c64cf498"),
               unhexlify(b"2d3b9f8856478700cff57fe02823dfc0a3650b6366aa2d553393928def0b0b21"),
               unhexlify(b"d2427d70146551596337bd4eb1e1283f5a1e9c224b02940a27926592ecaa0467"),
               unhexlify(b"09ab4ea74379eb1eb51f517c05d3cfa749b46bdae7b991257d6d83c38836521b"),
               ],
            R=[unhexlify(b"0723c20cf9f95ee679e84ff4f29bee238a6a25ed644c33ab4db414ffa473b4c7"),
               unhexlify(b"4952950ee116b5bde3e13e02f6f4d0d0ec712c2318375c7722bf146a40d76374"),
               unhexlify(b"a89f97efe6aea6436024caafb26d4d011bdfb63fae0fa88cf16930d063fd3313"),
               unhexlify(b"c0df5b538038fa72c81962e65a2026cb24f4046195e7e10184e0b13717985c29"),
               unhexlify(b"847fa298d27e4b3db9f3cc5f12edb6bf3cd59a479146445173ec5a35385fde37"),
               unhexlify(b"03e9a7f06209ca2cbfcb80c54b553ccdbb34a97f80b0744649f363be73aef34a"),
               ],
            a=unhexlify(b"6ee7caeac561702168b37ca0629b36b67786d8b3024853cc4d4f11abc27db606"),
            b=unhexlify(b"f0018fbc436d06205a947d84742acad9057bae87bba65962239203c57fecfc03"),
            t=unhexlify(b"a4605213f7bc9105f0f2d2311de353aad53b106227b7dff1177137626267ea01")
        )
        # fmt: on

        self.assertTrue(bpi.verify(bp_proof))

    def test_prove(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        val = crypto.sc_init(123)
        mask = crypto.sc_init(432)
        bpi.set_input(val, mask)
        bp_res = bpi.prove()
        bpi.verify(bp_res)

        try:
            bp_res.S[0] += 1
            bpi.verify(bp_res)
            self.fail("Verification should have failed")
        except:
            pass

    def test_prove_2(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        val = crypto.sc_init((1 << 30) - 1 + 16)
        mask = crypto.random_scalar()
        bpi.set_input(val, mask)
        bp_res = bpi.prove()
        bpi.verify(bp_res)

    def test_verify_batch_1(self):
        self.skip_if_cannot_test()
        proof1 = Bulletproof(
            V=[
                unhexlify(b"3c705e1da4bbe43a0535a5ad3a8e6c148fb8c1a4118ba6b65412b2fe6511b261"),
            ],
            A=unhexlify(b"8c05311efed953678c15c5abd6a7b4bc5de8146e1543e380fe07dc598df65084"),
            S=unhexlify(b"cf2435426c841e094d53ac1f900b4aeaf0678f6e75806da8b250e72d6b0db9fe"),
            T1=unhexlify(b"49e8d85264d5dfcdf50dc25fab6b2033925ff4cbf5fcf60ef38005aa17513b82"),
            T2=unhexlify(b"48803cbf46e21d0a4c887678cc59b2ef4ae6f8fa5e799d406590b648ac8201be"),
            taux=unhexlify(b"081f957b19e44ba9b7b24655fe3922daabfc1bab1c673e07dc2338f3e82ae301"),
            mu=unhexlify(b"84941385ca48731745006054eae175370a5f4de141f253f0f5c80169ba6ab806"),
            L=[unhexlify(b"f500b583f2632b4b8df16ff7a0b385f269d2af7697d0d880455e541e87cf7275"),
               unhexlify(b"48a9d34e919cef59f23d7f37bc065f65fa04eeeb16a23f189686068b94acca4c"),
               unhexlify(b"6b86649c1c3bdfd2b4127940d90d573dd5545edba42bf0bddccde32d4c3d31a9"),
               unhexlify(b"b5563c4953a2a038df85fd9fa9effc28e0a8d4fdbb0afd79f87c728e3baf26d6"),
               unhexlify(b"405c833acbc49260342efebfeb1d6d3f78bb14880dff91d2da6b48492b5c93e5"),
               unhexlify(b"3984b85b3aa86fce40be26a1906a5030e1c1f1f4c9754274ad653e8ccb19d77a"),
               ],
            R=[unhexlify(b"ec998c442b4f34ffd2c04cb841830f3327c2bd5155ab6b85831a2b007ac2241e"),
               unhexlify(b"176082c148ff8cb89e87eab5e1949482829a55cdf0bd0ad7de97dc3b96e51702"),
               unhexlify(b"e34bd13d7a3c2dea113e97ca2bd3b9f661242d378ddac04d7cc2c09ea5d3714c"),
               unhexlify(b"286d1b72503e0641eae2c986f00344130e1756dfe002c8b06f0df1e62cbefc70"),
               unhexlify(b"152948ab81532772646d40f44192da69122ae14c20b9fd0b52d969764d374a77"),
               unhexlify(b"6c97a306c3f03f15454fda896a6feb508c029463310d2d0205b55271db68df30"),
               ],
            a=unhexlify(b"8b25662dcd953095b799389336c1a9a4afc8540a250252b188d6311e2857e208"),
            b=unhexlify(b"64c38a82dc5e629168b0284e00d40df80b5d72fdf443e19e8a890d49692faa0d"),
            t=unhexlify(b"328effcadf4324536545ec9fc44216eb1041ef8474fa0f54b62b36ee08be4f0b")
        )

        proof2 = Bulletproof(
            V=[
                unhexlify(b"3c705e1da4bbe43a0535a5ad3a8e6c148fb8c1a4118ba6b65412b2fe6511b261"),
            ],
            A=unhexlify(b"7372db75c0d9d409524924fff5dd13e867eb4c5789f3f5cc6ef860be68d5e4e5"),
            S=unhexlify(b"be8f2d87ace0a528056d567881e74f44817a811e110cdb3890376262a2084ab3"),
            T1=unhexlify(b"8dfc541c379efbe6000bb2339c3a52288ffa4300fcc0f0f0de777e54b5488160"),
            T2=unhexlify(b"cf7d046c86c33bea6c5167bb6482c0a31332989dc9493eacc04a07deb6536953"),
            taux=unhexlify(b"abaaf209cc9a800d933d51bb398b81ee7284efc9c92727066a640fdccc954009"),
            mu=unhexlify(b"ec743e23abb555dca26164a86614306f117a733fcd395eb8675411cd31915608"),
            L=[unhexlify(b"0ee1acc28126656eaf0934314a97e1cf2232a13f5636d319a233cedd58b2882f"),
               unhexlify(b"cc3d2ec5635de569343bea37fc46a93413ae66bf803a4333f427f79f341d1696"),
               unhexlify(b"518c80669bed0960fd03e802a9e837e1aa4a4910bb5853067447d7d22eaca325"),
               unhexlify(b"251a586e8e79a5d767b89931e012acdae317c13c434a6f5f121e44b3b59240b2"),
               unhexlify(b"09b41426e6c9808f6a58ded987cc39936f703f136b50493dd1c92c9b1ec4e7fc"),
               unhexlify(b"984d1369c3c7f2687eebca26395576810c66623408958efde4f36b0bb63a2475"),
               ],
            R=[unhexlify(b"31768a0465315ff0dd1ea2228ae8c34d1474e873a863362feab7b050f29a211a"),
               unhexlify(b"27d1b2533ed78d3dacc396afa50fa533cffc5d1563b679a4049a482436718d3c"),
               unhexlify(b"a49388b042c8a4c6526054661fac1706cf450181ec1f9eed005b283614ec7f95"),
               unhexlify(b"3f053243fe16f8fd302395c125ffedd93831829b13abbb195bf69fc139069de9"),
               unhexlify(b"5a32d7f7132043d1f0cc8cd88cce94e5241337ed616c35a1d753436b2d1c4a93"),
               unhexlify(b"bbd7f9b3031cf41b613a9ee726de9693457238b4be6317083d278e00717f8c14"),
               ],
            a=unhexlify(b"83d8d128f35aa02fc063792df9f4e9de0d4e58b8c6e7c449a672d6e4286ee309"),
            b=unhexlify(b"741d679f1dfe749f7d1ede687f8dd48f7fd3b5a52a5e6a453488d5e25b3fff0e"),
            t=unhexlify(b"88331e9fd7573135016629f337240225f9c0a5b70bad4157ad60d4260feb2b03")
        )

        bpi = bp.BulletProofBuilder()
        bpi.verify_batch([proof1, proof2])

    def test_prove_random_masks(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        bpi.use_det_masks = False  # trully randomly generated mask vectors
        val = crypto.sc_init((1 << 30) - 1 + 16)
        mask = crypto.random_scalar()
        bpi.set_input(val, mask)
        bp_res = bpi.prove()
        bpi.verify(bp_res)

    def test_multiexp(self):
        self.skip_if_cannot_test()
        scalars = [0, 1, 2, 3, 4, 99]
        point_base = [0, 2, 4, 7, 12, 18]
        scalar_sc = [crypto.sc_init(x) for x in scalars]
        points = [crypto.scalarmult_base(crypto.sc_init(x)) for x in point_base]

        muex = bp.MultiExp(scalars=[crypto.encodeint(x) for x in scalar_sc],
                           point_fnc=lambda i, d: crypto.encodepoint(points[i]))

        self.assertEqual(len(muex), len(scalars))
        res = bp.multiexp(None, muex)
        res2 = bp.vector_exponent_custom(
            A=bp.KeyVEval(3, lambda i, d: crypto.encodepoint(crypto.scalarmult_base(crypto.sc_init(point_base[i])))),
            B=bp.KeyVEval(3, lambda i, d: crypto.encodepoint(crypto.scalarmult_base(crypto.sc_init(point_base[3+i])))),
            a=bp.KeyVEval(3, lambda i, d: crypto.encodeint(crypto.sc_init(scalars[i]))),
            b=bp.KeyVEval(3, lambda i, d: crypto.encodeint(crypto.sc_init(scalars[i+3]))),
        )
        self.assertEqual(res, res2)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
