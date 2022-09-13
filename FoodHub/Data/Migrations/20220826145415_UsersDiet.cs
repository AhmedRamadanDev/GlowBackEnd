using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FoodHub.Data.Migrations
{
    public partial class UsersDiet : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_diets_AspNetUsers_UserId",
                table: "diets");

            migrationBuilder.DropIndex(
                name: "IX_diets_UserId",
                table: "diets");

            migrationBuilder.DropColumn(
                name: "ClientId",
                table: "diets");

            migrationBuilder.DropColumn(
                name: "UserId",
                table: "diets");

            migrationBuilder.AddColumn<DateTime>(
                name: "Date",
                table: "diets",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.CreateTable(
                name: "Userdiet",
                columns: table => new
                {
                    DietsId = table.Column<int>(type: "int", nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Userdiet", x => new { x.DietsId, x.UserId });
                    table.ForeignKey(
                        name: "FK_Userdiet_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Userdiet_diets_DietsId",
                        column: x => x.DietsId,
                        principalTable: "diets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Userdiet_UserId",
                table: "Userdiet",
                column: "UserId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Userdiet");

            migrationBuilder.DropColumn(
                name: "Date",
                table: "diets");

            migrationBuilder.AddColumn<string>(
                name: "ClientId",
                table: "diets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "UserId",
                table: "diets",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_diets_UserId",
                table: "diets",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_diets_AspNetUsers_UserId",
                table: "diets",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
