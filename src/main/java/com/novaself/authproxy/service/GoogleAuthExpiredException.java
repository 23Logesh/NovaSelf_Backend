package com.novaself.authproxy.service;

public class GoogleAuthExpiredException extends RuntimeException {
    public GoogleAuthExpiredException() { super("Google access token rejected (401)"); }
}