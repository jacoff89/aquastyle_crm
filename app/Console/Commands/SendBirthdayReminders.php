<?php

namespace App\Console\Commands;

use App\Models\User;
use App\Notifications\BirthdayReminderInTelegram;
use App\Notifications\Telegram\TelegramBot;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Notification;

/**
 * Tells the instructors who linked Telegram that a colleague's birthday is coming, so that
 * they can congratulate them. It runs once a day (see routes/console.php).
 */
#[Signature('instructors:send-birthday-reminders')]
#[Description('Напомнить инструкторам в Telegram о предстоящих днях рождения коллег')]
class SendBirthdayReminders extends Command
{
    /**
     * How many days ahead the colleagues are told.
     */
    public const DAYS_AHEAD = 3;

    public function handle(TelegramBot $bot): int
    {
        if (! $bot->isConfigured()) {
            $this->warn('Бот не настроен: задайте TELEGRAM_BOT_TOKEN и TELEGRAM_BOT_USERNAME в .env.');

            return self::SUCCESS;
        }

        $day = today()->addDays(self::DAYS_AHEAD);
        $activeInstructors = User::instructors()->where('is_active', true)->get();
        $sent = 0;

        foreach ($activeInstructors->filter(fn (User $instructor): bool => $instructor->hasBirthdayOn($day)) as $birthdayPerson) {
            $colleagues = $activeInstructors->filter(
                fn (User $instructor): bool => $instructor->hasTelegram() && ! $instructor->is($birthdayPerson),
            );

            Notification::send($colleagues, new BirthdayReminderInTelegram($birthdayPerson, self::DAYS_AHEAD));
            $sent += $colleagues->count();
        }

        $this->info("Отправлено напоминаний: {$sent}.");

        return self::SUCCESS;
    }
}
