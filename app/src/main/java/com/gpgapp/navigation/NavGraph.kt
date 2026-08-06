package com.gpgapp.navigation

sealed class Screen(val route: String) {
    data object Home : Screen("home")
    data object KeyList : Screen("key_list")
    data object KeyDetail : Screen("key_detail/{keyId}") {
        fun createRoute(keyId: Long) = "key_detail/$keyId"
    }
    data object GenerateKey : Screen("generate_key")
    data object Encrypt : Screen("encrypt")
    data object Decrypt : Screen("decrypt")
}
