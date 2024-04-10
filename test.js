import {
	JWK,
	JWKS,
	JWE,
	errors
} from 'jose'
import { encryption as deriveKey } from './src/hkdf.js'
let current
// import jwtDecode from 'jwt-decode'

let keystore = new JWKS.KeyStore()

const alg = 'dir'
const enc = 'A256GCM'

const secrets = ['very-secret-12131415'];
secrets.forEach((secretString, i) => {
    const key = JWK.asKey(deriveKey(secretString))
    if (i === 0) {
        current = key
    }
    keystore.add(key)
})

const jwe = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiaWF0IjoxNjYyNTE3MjI2LCJ1YXQiOjE2NjI1MTcyMjYsImV4cCI6MTY2MjYwMzYyNn0..qBqfwTaB1kHt2wxK.qtXalhjGOy-lfQbLOg5PJyTcAN9Egwm33ELu7MTO8wcS16Z1qY8bLdDCtDsiBXT468n81YSiaAvHA53qEG-uCpbrqIvq5vaeYPYYCVxLjiWZT6CnIL05kevwMN5bzooVU4S000rj1pePsAWZh5SAKaia_qhb8q075Gb4PKtSXvhd6VGmkw6fhjLYJgZy0LEO1xi5urjKFMWb1UyFMZpxtnHHctygWjOG1ufYnYHzJ0N12dG9r3G3Lj1x8mgoNKT-rowoRVdpggQVLBCKrU-ZfjGRbkD3RmiUDaW_BtTLp_nCgwxjFx6XssxXca3Mqerg4uDxcNJ204nIDFsMuc6CR8WeWizCqItqCNR2BamxSPfthLH4gjgVAHmEzq7CeGI2jH4-u6U-mify8Q-Rbpu69G1cHW_k_2DD7c7eSW6ibig87Osk2wCsWqMGY-Cnmeta1M5rUwVqPDNtYj6iP15eldQ3ckftiLNWWcftJ6XKChlFixEmAViSKeOHEfR0i_288oE7IO_jeje2rTVnfTsKZII5WZ-REJU_KTbgQrqlmwrFmF73AF7zr_lo86eIkbSI9N12i_N4cYlH_9fUo2aRB29QKJ9bVkBbNm16CNmguEK8jcG2-s6pvjaBpeIOfbYAz9zwhICCZm10NYwmHkcpBoaDKIlCqbshj0R-piruMZnTwF6z8aYJfos5hTANw_aiwmEhChpIJX2kqHodq-NtV3EQdHCrJzSnTiqji1rJ2nb9BvWHIg86ZC33jBvkzmbqt-BElJS0yh-m8IRPn6OfqIYf1PFcHSSo--t5YDUlg8J9c35bv_u5C8iMe9HB-tFw7that9_lnCzw-7zbfZNFVZlPT7Ez7SwK9Q_Y3o7tIgA7v4pD2qeCf6yx9kgK7BDr9PUhjiP5zwTpJQiuzoZTnamX51GUuY-pbxFL_pxF_a31K8akiEU8vDRVWdfCm3BrMsvwf0idGOPmjDdEYAGOKKHtOGH2N-aZjVs5wf-ItC8cA6SPVBFlJWVGIAKmAtR8lCWelIe5o2KZqCAWAwbnFkIVASvXzI-v03-DAXRtba2NrO9qAz_-2HNCUzCu9nsfe1wZZOuia07SgGnz27QZW5nZkMO5JrsxadvUS9ItYrEaZsR-d-S0Z7_ZQXIlpO91jQ8Zoyh4uARpVwHxsruRqokFdO4yINQuEZl8E6d5mzXgFL5Egju7s7rcH00OpnxhnVJ6m6YZRgA3ep16KlnGlmkp83D-3ulPdfxQrrr7M5jTHCLVV8kj-7Sp9zDZhGYUrc4kaLTeH8LH-LptxTi0BMDTNDlXImbaVvMyXNvUZiAbs-rAbrPNxibTh1ey8AylVB0gHM7eKK6O_OEWcJWzOS2KifcdwJFWERsIOJv8R4IQ96xVsWPeLassOwE_kevK23GV1Vpcxk4m9UoKWZCr_yvPchjDsbYc1zywtq39lQ9D0v6m727OG7mB4jJuYjK6ggvXw35gc1xcVQyoz-RdhJyzG_UJXECAHhwaOptESNMy7mU9E1n5wr53ES_3LFDDpH9Kf5ACTOfjIj9b6NXlhZ7OFLYKvGbyEM7w-LGTNmXIjleXKjWgLUdpX2scGWsWk2C4DUFGPVvM29mFZqwN9TWG-sykor1R6NMGgzwAHlVcv3BbAXjlBeQKiohjHjic52_n0NqxwzDEulunCyUENIRSRw6s3TRJLgaN5WDhSu3a0MhcaZtful5-Z07P_0W_6xRCrWNuq0TCzDxqSxDvECbvQPOJIrfoUQ7O0VtW2akaglFJqNgbeAaYygGR3L79aRX7EKnqZXv_v7HnpzLV4YyYCJrQux-FukDNBZpQqI_wxWBrGS5eNmm961wIGTmrxoNO3lrJJpqmbDV2v5WNXv7DgTVT9lhBMfjwzaaNgV2w8-Cob-kjNjvohBQ6diD77BOL_WPgVk0XjEw1jCdNaYiHb7jCLteSbiwqOPsJsH7bIZ3vC5d4ZzYCnaIiRQLFNNJ-9vEoU1f2_mOPXdPTsuItdrTsnVGtXMeQ-OqkfjFIKQE_HDUVkY7_CvoTC1pvKJ__gM_mAYCDl0K0jruqTpUnuZrOlE8gBH3qEPU1YqzlXksFoYSk9EftW4LrldfaT9f20l_nrT1IelRsfxzJuiiDSi8Syhgl_emqamw2CeAYXZN8yPom9UPlf6uMyEMaVjNIcBFcpJc9uQcEd6Y_QShLUT81kyoYRDZ5qoCpreXzjoD8UgtYEogv16Mf24iQ73eWYr3-_mK2RAUoR-bPC5LiNCyac5l4MlItsGuZoC1UWlcdHeQ5wT06hER-__nxIOcsNZm92JFLTOjPZRlLsDIYg5AKjDV1qyYO0FWc84CxTm4RVDStuZu6GKCOWU5c9PiZobIo-08Hom_zFicRZJwUDQke4QjF5ohjuO02Oc8PFK67D922hujg7JtvPN3nuLs0fKgLXYDYo5UuVQzecl5NcokX6FVojI8YTFy812MQPDCXcZvCHDZvg6DIQtXdMNYskwu5jf-9rvvEyKQFsMoPPSm8sSz4SKXduT6hWq2H2JF34n6sh0wE6mhT9rQfKzykox_eFlM2R5P46u39gnasiEUT_Og3ZJTLHCbkTw0PSEKgGIGgMMsXNYwfxXU4j7yI2SfL0yR2p46-4p96Sr-T4bwfsZC9l1PKsT1tl4CaJYhaXpQd0wukBngg7wuPQL6vGS2dfjJpgfZusIv5Skuo4eighTE8WE96HybZtvVXAqzz5vrc0fDZfaQrGW5IYz11waVq3fAY64Q9z5Fc0ygJjFu6tCcZLcJpGk18KJlHMzZHxSLq8KP0kdXYHWkqp9-f9ztg2vUx-NgAICPwbRsXHupn5-fjgz4sFk08mfKaakSq8IZaBQV4GEuLergILwGnNBlg8J10wMZCdy2Xo5He7mM2TLFGtLa5bx6VIXj5jEbghdoXn2x8BC4qup8sC81ysspvuI7dOvvfOKo6vj0JczFc393SlwpgSGbUrfOBGds_QMix4L7zq1CisIic20dNIiBx.1E5lTqzmIrBRVmCctwUIkw'
const result = JWE.decrypt(jwe, keystore, {
    complete: true,
    contentEncryptionAlgorithms: [enc],
    keyManagementAlgorithms: [alg]
})
console.log(result)
console.log(result.cleartext.toString())
console.log(JSON.parse(result.cleartext))