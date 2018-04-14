# pubg_decryptor

3.7.28.13

```c
struct tsl tsl;

if (!tsl_init(&tsl)) {
  // what?
}

uint64_t uworld = READ64(READ64(g_base_addr + 0x40d1b20));
uint64_t level = tsl_decrypt_prop(&tsl, uworld + 0x30);
uint64_t game_inst = READ64(uworld + 0x148);
uint64_t local_player = tsl_decrypt_prop(&tsl, READ64(game_inst + 0x38));
uint64_t player_controller = tsl_decrypt_prop(&tsl, local_player + 0x30);
uint64_t player_camera_manager = READ64(player_controller + 0x498);
uint64_t viewport_client = READ64(local_player + 0x60);
uint64_t pworld = READ64(viewport_client + 0x80);

uint64_t actor = tsl_decrypt_actor(&tsl, level + 0xa0);
uint64_t actor_list = READ64(actor);
uint32_t actor_count = READ32(actor + 0x8);

uint64_t local_player_actor = tsl_decrypt_prop(&tsl, player_controller + 0x470);

uint64_t gnames = READ64(g_base_addr + 0x4142888);

tsl_finit(&tsl);
```
