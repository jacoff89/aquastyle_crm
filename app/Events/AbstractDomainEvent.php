<?php

namespace App\Events;

use App\Events\Concerns\DescribesEvents;
use App\Models\User;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * The common part of the application's domain events: who made the change and when,
 * and the wording their descriptions share.
 * Models in an event are serialized by key, so a queued listener gets them fresh from the database.
 */
abstract class AbstractDomainEvent implements DomainEvent
{
    use DescribesEvents, Dispatchable, SerializesModels;

    public CarbonImmutable $occurredAt;

    public function __construct(public ?User $actor)
    {
        $this->occurredAt = CarbonImmutable::now();
    }

    public function actor(): ?User
    {
        return $this->actor;
    }

    public function occurredAt(): CarbonImmutable
    {
        return $this->occurredAt;
    }
}
