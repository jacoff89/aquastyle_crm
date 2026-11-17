<?php

namespace App\Console\Commands;

use App\Enums\CommunicationStatus;
use App\Events\Communications\CommunicationDue;
use App\Models\Communication;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

/**
 * Announces the planned communications whose time has come, once each: the notice is created
 * and, for those who linked Telegram, sent there (see CreateNotice). It runs every minute
 * (see routes/console.php).
 */
#[Signature('communications:send-reminders')]
#[Description('Уведомить о запланированных коммуникациях, время которых наступило')]
class SendCommunicationReminders extends Command
{
    public function handle(): int
    {
        $sent = 0;

        Communication::query()
            ->where('status', CommunicationStatus::Planned)
            ->where('occurred_at', '<=', now())
            ->whereNull('reminded_at')
            ->each(function (Communication $communication) use (&$sent): void {
                $claimed = Communication::query()
                    ->whereKey($communication->getKey())
                    ->whereNull('reminded_at')
                    ->update(['reminded_at' => now()]);

                if ($claimed === 1) {
                    CommunicationDue::dispatch($communication);
                    $sent++;
                }
            });

        $this->info("Отправлено напоминаний: {$sent}.");

        return self::SUCCESS;
    }
}
