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
        Schema::create('events', function (Blueprint $table) {
            $table->id();
            $table->string('title')->nullable();
            $table->foreignId('event_type_id')->constrained()->restrictOnDelete();
            $table->dateTime('starts_at');
            $table->dateTime('ends_at');
            $table->string('location')->nullable();
            $table->unsignedSmallInteger('capacity')->nullable();
            $table->string('status', 20)->default('planned');
            $table->text('notes')->nullable();
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index(['starts_at', 'ends_at']);
        });

        Schema::create('event_instructor', function (Blueprint $table) {
            $table->id();
            $table->foreignId('event_id')->constrained()->cascadeOnDelete();
            $table->foreignId('user_id')->constrained()->restrictOnDelete();
            $table->string('role', 20);

            $table->unique(['event_id', 'user_id']);
            $table->index('user_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('event_instructor');
        Schema::dropIfExists('events');
    }
};
