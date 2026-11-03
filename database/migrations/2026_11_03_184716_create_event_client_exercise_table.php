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
        Schema::create('event_client_exercise', function (Blueprint $table) {
            $table->id();
            $table->foreignId('event_client_id')->constrained('event_client')->cascadeOnDelete();
            $table->foreignId('exercise_id')->constrained()->restrictOnDelete();

            $table->unique(['event_client_id', 'exercise_id']);
            $table->index('exercise_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('event_client_exercise');
    }
};
