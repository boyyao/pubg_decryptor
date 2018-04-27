# pubg_decryptor

- 3.7.33.27

```c
struct tsl tsl;
 
if (!tsl_init(&tsl)) {
  // what?
}
 
uint64_t world = READ64(READ64(g_base_addr + 0x4188a80));
uint64_t level = tsl_decrypt_prop(&tsl, world + 0xb0);
uint64_t game_inst = tsl_decrypt_prop(&tsl, world + 0x190);
uint64_t local_player = tsl_decrypt_prop(&tsl, READ64(game_inst + 0xd0));
uint64_t player_controller = tsl_decrypt_prop(&tsl, local_player + 0x30);
uint64_t player_camera_manager = READ64(player_controller + 0x4d8);
uint64_t viewport_client = tsl_decrypt_prop(&tsl, local_player + 0xd0);
uint64_t pworld = READ64(viewport_client + 0x90);
 
uint64_t actor = tsl_decrypt_actor(&tsl, level + 0x1c0);
uint64_t actor_list = READ64(actor);
uint32_t actor_count = READ32(actor + 0x8);
 
uint64_t local_player_actor = tsl_decrypt_prop(&tsl, player_controller + 0x4b0);
 
uint64_t gnames = READ64(g_base_addr + 0x41f9808);
 
tsl_finit(&tsl);
```
