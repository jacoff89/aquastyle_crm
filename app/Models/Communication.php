<?php

namespace App\Models;

use App\Enums\CommunicationChannel;
use App\Enums\CommunicationStatus;
use Carbon\CarbonInterface;
use Database\Factories\CommunicationFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A record of contact with a client: a call, a message, a meeting and what was said.
 * A client has many; they are shown on the client's card after the visit history.
 */
#[Fillable(['channel', 'status', 'occurred_at', 'notes'])]
class Communication extends Model
{
    /** @use HasFactory<CommunicationFactory> */
    use HasFactory;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'channel' => CommunicationChannel::class,
            'status' => CommunicationStatus::class,
            'occurred_at' => 'datetime',
            'reminded_at' => 'datetime',
        ];
    }

    /**
     * Moving a communication to another time or back to "planned" makes its reminder due again.
     */
    protected static function booted(): void
    {
        static::saving(function (Communication $communication): void {
            if ($communication->exists && ! $communication->isDirty('reminded_at') && $communication->isDirty(['status', 'occurred_at'])) {
                $communication->reminded_at = null;
            }
        });
    }

    /**
     * @return BelongsTo<Client, $this>
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class);
    }

    /**
     * The user who recorded the communication.
     *
     * @return BelongsTo<User, $this>
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * Communications whose time falls in [$start, $end).
     *
     * @param  Builder<Communication>  $query
     */
    #[Scope]
    protected function occurredBetween(Builder $query, CarbonInterface $start, CarbonInterface $end): void
    {
        $query->where('occurred_at', '>=', $start)->where('occurred_at', '<', $end);
    }

    /**
     * The latest first.
     *
     * @param  Builder<Communication>  $query
     */
    #[Scope]
    protected function latestFirst(Builder $query): void
    {
        $query->orderByDesc('occurred_at')->orderByDesc('id');
    }
}
