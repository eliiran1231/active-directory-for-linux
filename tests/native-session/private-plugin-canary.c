/* Harmless loadable module: only its constructor changes this local integer. */
int adfl_canary_loaded;
__attribute__((constructor)) static void loaded(void) { adfl_canary_loaded = 1; }
