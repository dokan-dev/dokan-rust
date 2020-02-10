#include <stdio.h>
#include "dokan.h"

int main() {
	FILE *version_file = fopen("version.rs", "w");
	if (version_file == NULL) return 1;
	fprintf(version_file, "pub const DOKAN_VERSION: u32 = %d;\n", DOKAN_VERSION);
	fprintf(version_file, "pub const DOKAN_MINIMUM_COMPATIBLE_VERSION: u32 = %d;\n", DOKAN_MINIMUM_COMPATIBLE_VERSION);
	fprintf(version_file, "pub const DOKAN_DRIVER_NAME: &str = \"%ls\";\n", DOKAN_DRIVER_NAME);
	fprintf(version_file, "pub const DOKAN_NP_NAME: &str = \"%ls\";\n", DOKAN_NP_NAME);
	fprintf(version_file, "pub const DOKAN_MAJOR_API_VERSION: &str = \"%ls\";\n", DOKAN_MAJOR_API_VERSION);
	fclose(version_file);

	FILE *major_version_file = fopen("version_major.txt", "w");
	if (major_version_file == NULL) return 1;
	fprintf(major_version_file, "%ls", DOKAN_MAJOR_API_VERSION);
	fclose(major_version_file);

	return 0;
}
