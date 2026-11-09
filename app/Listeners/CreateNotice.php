<?php

namespace App\Listeners;

use App\Events\DomainEvent;
use App\Events\EventPayload;
use App\Models\Notice;
use App\Models\User;
use App\Notifications\NoticeInTelegram;
use App\Notifications\Telegram\TelegramBot;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;

/**
 * Turns every domain event into a notice: its description, the users it concerns
 * and the event's data for later use. The author of the change gets the notice already read.
 *
 * It runs on the queue, so that a failure here never breaks the request that made the change.
 * The event's models are loaded fresh by then, which is what the description should show anyway.
 *
 * Once the notice is saved, it goes to Telegram to those who chose its type, each through a job of its own.
 */
class CreateNotice implements ShouldQueue
{
    public function __construct(private TelegramBot $telegram) {}

    public function handle(DomainEvent $event): void
    {
        $description = $event->describe();

        if ($description === null) {
            return;
        }

        $notice = DB::transaction(function () use ($event, $description): Notice {
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

            return $notice;
        });

        if ($this->telegram->isConfigured()) {
            Notification::send($notice->telegramRecipients(), new NoticeInTelegram($notice));
        }
    }
}
