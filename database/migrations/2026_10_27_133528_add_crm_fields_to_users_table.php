<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('phone', 32)->nullable()->after('email');
            $table->string('role', 20)->default('instructor')->after('phone');
            $table->boolean('is_active')->default(true)->after('role');
            $table->string('color', 7)->nullable()->after('is_active');
            $table->text('notes')->nullable()->after('color');
            $table->foreignId('created_by')->nullable()->after('notes')->constrained('users')->nullOnDelete();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropConstrainedForeignId('created_by');
            $table->dropColumn(['phone', 'role', 'is_active', 'color', 'notes']);
        });
    }
};
