requires "Cwd";
requires "File::Copy";
requires "File::Spec";

on 'develop' => sub {
	requires "Module::Install";
	requires "Module::Install::CheckLib";

	requires "Test::Spelling";
};