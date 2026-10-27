<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * A user can now hold several roles at once, e.g. an administrator who also
 * teaches. The single `role` column becomes a JSON list `roles`.
 */
return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->json('roles')->nullable()->after('phone');
        });

        DB::table('users')->where('role', 'admin')->update(['roles' => json_encode(['admin'])]);
        DB::table('users')->where('role', '!=', 'admin')->update(['roles' => json_encode(['instructor'])]);

        Schema::table('users', function (Blueprint $table) {
            $table->json('roles')->nullable(false)->change();
        });

        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('role');
        });
    }

    /**
     * Reverse the migrations. An administrator who also teaches goes back to being an administrator.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('role', 20)->default('instructor')->after('phone');
        });

        DB::table('users')->whereJsonContains('roles', 'admin')->update(['role' => 'admin']);

        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('roles');
        });
    }
};
