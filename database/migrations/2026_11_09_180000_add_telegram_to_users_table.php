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
            // The private chat with the bot that notices are sent to; one chat belongs to one account.
            $table->bigInteger('telegram_chat_id')->nullable()->unique()->after('schedule_range');
            $table->string('telegram_username')->nullable()->after('telegram_chat_id');
            // Which notice types the user wants in Telegram: {"ClientBooked": "mine", ...}; null until they choose.
            $table->json('telegram_notices')->nullable()->after('telegram_username');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropUnique(['telegram_chat_id']);
            $table->dropColumn(['telegram_chat_id', 'telegram_username', 'telegram_notices']);
        });
    }
};
