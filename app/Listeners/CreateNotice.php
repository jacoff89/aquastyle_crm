<?php

namespace App\Listeners;

use App\Events\DomainEvent;
use App\Events\EventPayload;
use App\Models\Notice;
use App\Models\User;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\DB;

/**
 * Turns every domain event into a notice: its description, the users it concerns
 * and the event's data for later use. The author of the change gets the notice already read.
 *
 * It runs on the queue, so that a failure here never breaks the request that made the change.
 * The event's models are loaded fresh by then, which is what the description should show anyway.
 */
class CreateNotice implements ShouldQueue
{
    public function handle(DomainEvent $event): void
    {
        $description = $event->describe();

        if ($description === null) {
            return;
        }

        DB::transaction(function () use ($event, $description): void {
            $notice = Notice::create([
                'type' => class_basename($event),
                'message' => $description->text,
                'url' => $description->url,
                'url_for_concerned' => $description->urlForConcerned,
                'actor_id' => $event->actor()?->getKey(),
                'data' => EventPayload::of($event),
                'created_at' => $event->occurredAt(),
            ]);

            $notice->recipients()->attach(User::query()->whereKey($description->concernedUserIds)->pluck('id'));

            if ($event->actor() !== null) {
                $notice->markAsReadBy($event->actor());
            }
        });
    }
}
