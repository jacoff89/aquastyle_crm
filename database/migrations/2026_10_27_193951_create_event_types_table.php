<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Starter set of event types. Created here rather than in a seeder
     * so production gets them too; administrators edit the list afterwards.
     *
     * @var list<string>
     */
    private const STARTER_TYPES = [
        'Теория',
        'Бассейн',
        'Открытая вода',
        'Пробное погружение',
        'Прочее',
    ];

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('event_types', function (Blueprint $table) {
            $table->id();
            $table->string('name', 100)->unique();
            $table->unsignedInteger('sort_order')->default(0);
            $table->boolean('is_active')->default(true);
            $table->timestamps();
        });

        $now = now();

        DB::table('event_types')->insert(array_map(
            fn (string $name, int $index): array => [
                'name' => $name,
                'sort_order' => $index + 1,
                'is_active' => true,
                'created_at' => $now,
                'updated_at' => $now,
            ],
            self::STARTER_TYPES,
            array_keys(self::STARTER_TYPES),
        ));
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('event_types');
    }
};
