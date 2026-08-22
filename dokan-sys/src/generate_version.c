#include <stdio.h>
#include "dokan.h"

int main() {
	FILE *version_rs = fopen("version.rs", "w");
	if (version_rs == NULL) return 1;
	fprintf(version_rs, "/// Bundled Dokany API version without dots.\n");
	fprintf(version_rs, "pub const DOKAN_VERSION: u32 = %d;\n", DOKAN_VERSION);
	fprintf(version_rs, "/// Oldest Dokany API version accepted by the bundled library.\n");
	fprintf(version_rs, "pub const DOKAN_MINIMUM_COMPATIBLE_VERSION: u32 = %d;\n", DOKAN_MINIMUM_COMPATIBLE_VERSION);
	fprintf(version_rs, "/// Filename of the Dokany filesystem driver.\n");
	fprintf(version_rs, "pub const DOKAN_DRIVER_NAME: &str = \"%ls\";\n", DOKAN_DRIVER_NAME);
	fprintf(version_rs, "/// Display name of the Dokany network provider.\n");
	fprintf(version_rs, "pub const DOKAN_NP_NAME: &str = \"%ls\";\n", DOKAN_NP_NAME);
	fprintf(version_rs, "/// Major Dokany API version used in library and driver names.\n");
	fprintf(version_rs, "pub const DOKAN_MAJOR_API_VERSION: &str = \"%ls\";\n", DOKAN_MAJOR_API_VERSION);
	fclose(version_rs);

	FILE *version_txt = fopen("version.txt", "w");
	if (version_txt == NULL) return 1;
	fprintf(version_txt, "%d", DOKAN_VERSION);
	fclose(version_txt);

	return 0;
}
