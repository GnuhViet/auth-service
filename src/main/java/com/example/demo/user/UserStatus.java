package com.example.demo.user;

public enum UserStatus {
    Active(Constants.ACTIVE),
    Inactive(Constants.INACTIVE);

    UserStatus(String label) {
    }
    public static class Constants {
        public static final String ACTIVE = "ACTIVE";
        public static final String INACTIVE = "INACTIVE";
    }
}
