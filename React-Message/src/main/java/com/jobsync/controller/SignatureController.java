package com.jobsync.controller;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class SignatureController {

    private final KeyPair keyPair;

    public SignatureController() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.keyPair = keyGen.generateKeyPair();
    }

    @PostMapping("/sign")
    public Map<String, String> signMessage(@RequestBody Map<String, String> payload) throws Exception {
        String message = payload.get("message");
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(keyPair.getPrivate());
        privateSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        String encodedSignature = Base64.getEncoder().encodeToString(signature);

        Map<String, String> response = new HashMap<>();
        response.put("signature", encodedSignature);
        return response;
    }
    
    @PostMapping("/verify")
    public Map<String, Object> verifySignature(@RequestBody Map<String, String> payload) throws Exception {
        String message = payload.get("message");
        String signatureStr = payload.get("signature");

        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(keyPair.getPublic());
        publicSignature.update(message.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
        boolean isVerified = publicSignature.verify(signatureBytes);

        Map<String, Object> response = new HashMap<>();
        response.put("verified", isVerified);
        return response;
    }
}
