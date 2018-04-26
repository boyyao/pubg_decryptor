# pubg_decryptor

- 3.7.33.24

```c
struct tsl tsl;

if (!tsl_init(&tsl)) {
  // what?
}

uint64_t world = READ64(READ64(g_base_addr + 0x4169a80));
uint64_t level = tsl_decrypt_prop(&tsl, world + 0x140);
uint64_t game_inst = tsl_decrypt_prop(&tsl, world + 0xd0);
uint64_t local_player = tsl_decrypt_prop(&tsl, READ64(game_inst + 0xa0));
uint64_t player_controller = tsl_decrypt_prop(&tsl, local_player + 0x30);
uint64_t player_camera_manager = READ64(player_controller + 0x4a8);
uint64_t viewport_client = tsl_decrypt_prop(&tsl, local_player + 0xa0);
uint64_t pworld = READ64(viewport_client + 0x98);

uint64_t actor = tsl_decrypt_actor(&tsl, level + 0xc0);
uint64_t actor_list = READ64(actor);
uint32_t actor_count = READ32(actor + 0x8);

uint64_t local_player_actor = tsl_decrypt_prop(&tsl, player_controller + 0x480);

uint64_t gnames = READ64(g_base_addr + 0x41da808);

tsl_finit(&tsl);
```
