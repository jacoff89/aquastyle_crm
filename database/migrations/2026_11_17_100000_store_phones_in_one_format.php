<?php

use App\Casts\PhoneNumber;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Phones of clients and users are stored in E.164 ("+79123456789"), so `clients.phone_digits` is no longer needed.
     * A number that cannot be recognized is left as it was and written to the log, to be fixed by hand:
     * the form will not save the card until the number is valid.
     */
    public function up(): void
    {
        $this->normalizeColumn('clients');
        $this->normalizeColumn('users');

        Schema::table('clients', function (Blueprint $table) {
            $table->dropIndex(['phone_digits']);
        });

        Schema::table('clients', function (Blueprint $table) {
            $table->dropColumn('phone_digits');
            $table->index('phone');
        });
    }

    /**
     * The phones stay in E.164: the way they were typed is not kept.
     */
    public function down(): void
    {
        Schema::table('clients', function (Blueprint $table) {
            $table->dropIndex(['phone']);
            $table->string('phone_digits', 20)->nullable()->after('phone')->index();
        });

        DB::table('clients')->whereNotNull('phone')->orderBy('id')->each(function (object $client): void {
            DB::table('clients')->where('id', $client->id)->update(['phone_digits' => ltrim($client->phone, '+')]);
        });
    }

    private function normalizeColumn(string $table): void
    {
        $unrecognized = [];

        DB::table($table)->whereNotNull('phone')->orderBy('id')->each(function (object $row) use ($table, &$unrecognized): void {
            $normalized = PhoneNumber::normalize($row->phone);

            if ($normalized === null) {
                $unrecognized[$row->id] = $row->phone;

                return;
            }

            if ($normalized !== $row->phone) {
                DB::table($table)->where('id', $row->id)->update(['phone' => $normalized]);
            }
        });

        if ($unrecognized !== []) {
            Log::warning("Phones in `{$table}` that are not valid and were left as they were (id => phone).", $unrecognized);
        }
    }
};
