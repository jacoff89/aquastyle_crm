<?php

namespace App\Models;

use App\Casts\PhoneNumber;
use Database\Factories\ClientFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * A person who attends the dive center's classes. Clients are soft-deleted,
 * so the history of their classes stays intact.
 *
 * The phone is the main key for search and for finding duplicates. It is stored
 * in one form only, E.164 ("+79123456789"), whatever way it was typed.
 *
 * A client may have a parent (one level only). A child can be saved without a phone.
 */
#[Fillable(['parent_id', 'last_name', 'first_name', 'middle_name', 'phone', 'email', 'birth_date', 'notes'])]
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
            'phone' => PhoneNumber::class,
        ];
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
     * The parent client, if this one is a child.
     *
     * @return BelongsTo<Client, $this>
     */
    public function parent(): BelongsTo
    {
        return $this->belongsTo(self::class, 'parent_id');
    }

    /**
     * The clients who are children of this one.
     *
     * @return HasMany<Client, $this>
     */
    public function children(): HasMany
    {
        return $this->hasMany(self::class, 'parent_id');
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
            ->withPivot('id', 'status', 'notes');
    }

    /**
     * The recorded contacts with the client.
     *
     * @return HasMany<Communication, $this>
     */
    public function communications(): HasMany
    {
        return $this->hasMany(Communication::class);
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
                    $query->orWhereRaw("phone like ? escape '!'", ['%'.$digits.'%']);

                    // "8912…" is how a Russian number is often typed; it is stored as "+7912…".
                    if (str_starts_with($digits, '8')) {
                        $query->orWhereRaw("phone like ? escape '!'", ['%7'.substr($digits, 1).'%']);
                    }
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
        $normalized = PhoneNumber::normalize($phone);

        if ($normalized === null) {
            $query->whereRaw('0 = 1');

            return;
        }

        $query->where('phone', $normalized);
    }

    /**
     * Make "%", "_" and the escape character itself ordinary characters in a LIKE pattern.
     */
    private static function escapeLike(string $value): string
    {
        return str_replace(['!', '%', '_'], ['!!', '!%', '!_'], $value);
    }
}
