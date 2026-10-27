<?php

namespace App\Models;

use Database\Factories\ClientFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * A person who attends the dive center's classes. Clients are soft-deleted,
 * so the history of their classes stays intact.
 *
 * The phone is the main key for search and for finding duplicates. It is kept
 * as typed, and `phone_digits` holds its normalized form for matching.
 */
#[Fillable(['last_name', 'first_name', 'middle_name', 'phone', 'email', 'birth_date', 'notes'])]
class Client extends Model
{
    /** @use HasFactory<ClientFactory> */
    use HasFactory, SoftDeletes;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'birth_date' => 'date',
        ];
    }

    /**
     * Keep the normalized phone in step with the phone as typed. A mutator is used
     * instead of a model event, so that seeding without events fills it in too.
     *
     * @return Attribute<string, string>
     */
    protected function phone(): Attribute
    {
        return Attribute::set(fn (string $value): array => [
            'phone' => $value,
            'phone_digits' => static::normalizePhone($value),
        ]);
    }

    /**
     * Reduce a phone number to digits so that "+7 912 345-67-89", "8 (912) 345-67-89"
     * and "9123456789" are the same number. Russian numbers are brought to the 7XXXXXXXXXX form.
     */
    public static function normalizePhone(string $phone): string
    {
        $digits = (string) preg_replace('/\D+/', '', $phone);

        if (strlen($digits) === 11 && str_starts_with($digits, '8')) {
            return '7'.substr($digits, 1);
        }

        if (strlen($digits) === 10) {
            return '7'.$digits;
        }

        return $digits;
    }

    /**
     * The user who added the client.
     *
     * @return BelongsTo<User, $this>
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * The events the client is booked on; their attendance status is in `pivot->status`.
     *
     * @return BelongsToMany<Event, $this, EventClient, 'pivot'>
     */
    public function events(): BelongsToMany
    {
        return $this->belongsToMany(Event::class, 'event_client')
            ->using(EventClient::class)
            ->withPivot('status', 'notes');
    }

    /**
     * Last name, first name and middle name in one line.
     */
    public function fullName(): string
    {
        return implode(' ', array_filter([$this->last_name, $this->first_name, $this->middle_name]));
    }

    /**
     * Find clients by any part of the name, the phone or the email. Every word
     * of the term has to match something, so "Иванов Пётр" narrows the list.
     *
     * @param  Builder<Client>  $query
     */
    #[Scope]
    protected function search(Builder $query, ?string $term): void
    {
        $words = preg_split('/\s+/', trim((string) $term), -1, PREG_SPLIT_NO_EMPTY);

        foreach ($words as $word) {
            $query->where(function (Builder $query) use ($word): void {
                $pattern = '%'.static::escapeLike($word).'%';

                foreach (['last_name', 'first_name', 'middle_name', 'email'] as $column) {
                    $query->orWhereRaw("{$column} like ? escape '!'", [$pattern]);
                }

                $digits = preg_replace('/\D+/', '', $word);

                if ($digits !== '') {
                    $query->orWhereRaw("phone_digits like ? escape '!'", ['%'.$digits.'%']);
                }
            });
        }
    }

    /**
     * Clients whose phone is the same number, however it was typed.
     *
     * @param  Builder<Client>  $query
     */
    #[Scope]
    protected function samePhoneAs(Builder $query, string $phone): void
    {
        $query->where('phone_digits', static::normalizePhone($phone));
    }

    /**
     * Make "%", "_" and the escape character itself ordinary characters in a LIKE pattern.
     */
    private static function escapeLike(string $value): string
    {
        return str_replace(['!', '%', '_'], ['!!', '!%', '!_'], $value);
    }
}
